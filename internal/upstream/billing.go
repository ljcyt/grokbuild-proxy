package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// MonthlyBilling is the default GET /v1/billing payload (subscription credits).
type MonthlyBilling struct {
	MonthlyLimit       *float64 `json:"monthlyLimit,omitempty"`
	Used               *float64 `json:"used,omitempty"`
	OnDemandCap        *float64 `json:"onDemandCap,omitempty"`
	BillingPeriodStart string   `json:"billingPeriodStart,omitempty"`
	BillingPeriodEnd   string   `json:"billingPeriodEnd,omitempty"`
	// Raw keeps unknown fields for forward compatibility.
	Raw map[string]json.RawMessage `json:"raw,omitempty"`
}

// WeeklyCredits is GET /v1/billing?format=credits.
type WeeklyCredits struct {
	CreditUsagePercent *float64                   `json:"creditUsagePercent,omitempty"`
	BillingPeriodEnd   string                     `json:"billingPeriodEnd,omitempty"`
	CurrentPeriod      json.RawMessage            `json:"currentPeriod,omitempty"`
	ProductUsage       []ProductUsage             `json:"productUsage,omitempty"`
	Raw                map[string]json.RawMessage `json:"raw,omitempty"`
}

type ProductUsage struct {
	Product      string                     `json:"product"`
	UsagePercent *float64                   `json:"usagePercent,omitempty"`
	Raw          map[string]json.RawMessage `json:"raw,omitempty"`
}

type GrokBuildQuota struct {
	Reported                 bool     `json:"reported"`
	SharedWeeklyUsagePercent *float64 `json:"shared_weekly_usage_percent,omitempty"`
	GrokBuildContribution    *float64 `json:"grok_build_contribution_percent,omitempty"`
	PeriodEnd                string   `json:"period_end,omitempty"`
	Note                     string   `json:"note"`
}

// BillingSnapshot combines monthly + optional weekly views.
type BillingSnapshot struct {
	Monthly      *MonthlyBilling `json:"monthly,omitempty"`
	Weekly       *WeeklyCredits  `json:"weekly,omitempty"`
	MonthlyError string          `json:"monthly_error,omitempty"`
	WeeklyError  string          `json:"weekly_error,omitempty"`
	GrokBuild    GrokBuildQuota  `json:"grok_build"`
}

// GetBilling fetches monthly billing for the given access token.
func (c *Client) GetBilling(ctx context.Context, accessToken string) (*MonthlyBilling, error) {
	status, _, raw, err := c.DoJSON(ctx, http.MethodGet, "/billing", nil, RequestOptions{
		AccessToken: accessToken,
		Accept:      "application/json",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "upstream billing", StatusCode: status, Body: truncate(string(raw), 512),
		}
	}
	return ParseMonthlyBilling(raw)
}

// GetBillingCredits fetches weekly credit usage (?format=credits).
func (c *Client) GetBillingCredits(ctx context.Context, accessToken string) (*WeeklyCredits, error) {
	status, _, raw, err := c.DoJSON(ctx, http.MethodGet, "/billing?format=credits", nil, RequestOptions{
		AccessToken: accessToken,
		Accept:      "application/json",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &HTTPStatusError{
			Operation: "upstream billing credits", StatusCode: status, Body: truncate(string(raw), 512),
		}
	}
	return ParseWeeklyCredits(raw)
}

// GetBillingSnapshot fetches monthly billing and best-effort weekly credits.
func (c *Client) GetBillingSnapshot(ctx context.Context, accessToken string) (*BillingSnapshot, error) {
	monthly, monthlyErr := c.GetBilling(ctx, accessToken)
	weekly, weeklyErr := c.GetBillingCredits(ctx, accessToken)
	snap := &BillingSnapshot{Monthly: monthly, Weekly: weekly}
	if monthlyErr != nil {
		snap.MonthlyError = safeBillingError(monthlyErr)
	}
	if weeklyErr != nil {
		snap.WeeklyError = safeBillingError(weeklyErr)
	}
	if monthlyErr != nil && weeklyErr != nil {
		return nil, fmt.Errorf("billing unavailable: monthly: %w; weekly: %v", monthlyErr, weeklyErr)
	}
	snap.GrokBuild = normalizeGrokBuild(weekly)
	return snap, nil
}

// ParseMonthlyBilling parses a /billing JSON body.
//
// Supports:
//   - flat: {"monthlyLimit":4000,"used":1421,...}
//   - nested config: {"config":{...}}
//   - protobuf-ish numbers: {"monthlyLimit":{"val":20000},"used":{"val":2704}}
func ParseMonthlyBilling(raw []byte) (*MonthlyBilling, error) {
	if len(bytesTrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("upstream billing: empty body")
	}
	root, err := billingObject(raw, "upstream billing")
	if err != nil {
		return nil, err
	}
	cfg := root
	if nested, ok := root["config"]; ok {
		obj, err := billingObject(nested, "upstream billing config")
		if err != nil {
			return nil, err
		}
		cfg = obj
	}

	out := &MonthlyBilling{}
	if out.MonthlyLimit, err = billingNumberField(cfg, "upstream billing", "monthlyLimit", "monthly_limit"); err != nil {
		return nil, err
	}
	if out.Used, err = billingNumberField(cfg, "upstream billing", "used"); err != nil {
		return nil, err
	}
	if out.OnDemandCap, err = billingNumberField(cfg, "upstream billing", "onDemandCap", "on_demand_cap"); err != nil {
		return nil, err
	}
	if out.BillingPeriodStart, err = billingStringField(cfg, "upstream billing", "billingPeriodStart", "billing_period_start"); err != nil {
		return nil, err
	}
	if out.BillingPeriodEnd, err = billingStringField(cfg, "upstream billing", "billingPeriodEnd", "billing_period_end"); err != nil {
		return nil, err
	}
	// Keep the original root shape, including a possible config wrapper and
	// unknown wrapper fields, so Admin diagnostics do not discard protocol data.
	out.Raw = cloneRawMap(root)
	return out, nil
}

// ParseWeeklyCredits parses a /billing?format=credits body.
//
// Supports flat fields and nested {"config":{...}} with optional {"val":N} wrappers.
func ParseWeeklyCredits(raw []byte) (*WeeklyCredits, error) {
	if len(bytesTrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("upstream billing credits: empty body")
	}
	root, err := billingObject(raw, "upstream billing credits")
	if err != nil {
		return nil, err
	}
	cfg := root
	if nested, ok := root["config"]; ok {
		obj, err := billingObject(nested, "upstream billing credits config")
		if err != nil {
			return nil, err
		}
		cfg = obj
	}

	out := &WeeklyCredits{}
	if out.CreditUsagePercent, err = billingNumberField(cfg, "upstream billing credits", "creditUsagePercent", "credit_usage_percent"); err != nil {
		return nil, err
	}
	if out.BillingPeriodEnd, err = billingStringField(cfg, "upstream billing credits", "billingPeriodEnd", "billing_period_end"); err != nil {
		return nil, err
	}
	if period, ok := cfg["currentPeriod"]; ok {
		out.CurrentPeriod = append(json.RawMessage(nil), period...)
	} else if period, ok := cfg["current_period"]; ok {
		out.CurrentPeriod = append(json.RawMessage(nil), period...)
	}
	pu := cfg["productUsage"]
	if len(pu) == 0 {
		pu = cfg["product_usage"]
	}
	if len(pu) > 0 && string(bytesTrimSpace(pu)) != "null" {
		var products []json.RawMessage
		if err := json.Unmarshal(pu, &products); err != nil {
			return nil, fmt.Errorf("upstream billing credits: productUsage must be an array: %w", err)
		}
		out.ProductUsage = make([]ProductUsage, len(products))
		for i, productJSON := range products {
			raw, err := billingObject(productJSON, fmt.Sprintf("upstream billing credits productUsage[%d]", i))
			if err != nil {
				return nil, err
			}
			product, err := billingStringField(raw, "upstream billing credits", "product", "name")
			if err != nil {
				return nil, err
			}
			usage, err := billingNumberField(raw, "upstream billing credits", "usagePercent", "usage_percent")
			if err != nil {
				return nil, err
			}
			out.ProductUsage[i] = ProductUsage{Product: product, UsagePercent: usage, Raw: cloneRawMap(raw)}
		}
	}
	sort.SliceStable(out.ProductUsage, func(i, j int) bool {
		leftBuild := isGrokBuildProduct(out.ProductUsage[i].Product)
		rightBuild := isGrokBuildProduct(out.ProductUsage[j].Product)
		if leftBuild != rightBuild {
			return leftBuild
		}
		return strings.ToLower(out.ProductUsage[i].Product) < strings.ToLower(out.ProductUsage[j].Product)
	})
	// Keep the original root shape, including a possible config wrapper and
	// unknown wrapper fields, so Admin diagnostics do not discard protocol data.
	out.Raw = cloneRawMap(root)
	return out, nil
}

func billingObject(raw []byte, operation string) (map[string]json.RawMessage, error) {
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s: expected JSON object", operation)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", operation, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%s: expected JSON object", operation)
	}
	return m, nil
}

// numberFromAny accepts JSON number or {"val": number|string}.
func numberFromAny(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return f, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
			return parsed, true
		}
	}
	var wrap struct {
		Val json.RawMessage `json:"val"`
	}
	if err := json.Unmarshal(raw, &wrap); err == nil && len(wrap.Val) > 0 {
		return numberFromAny(wrap.Val)
	}
	return 0, false
}

func billingNumberField(object map[string]json.RawMessage, operation string, keys ...string) (*float64, error) {
	for _, key := range keys {
		raw, exists := object[key]
		if !exists || string(bytesTrimSpace(raw)) == "null" {
			continue
		}
		value, ok := numberFromAny(raw)
		if !ok {
			return nil, fmt.Errorf("%s: %s must be a finite number", operation, key)
		}
		return floatPointer(value), nil
	}
	return nil, nil
}

func billingStringField(object map[string]json.RawMessage, operation string, keys ...string) (string, error) {
	for _, key := range keys {
		raw, exists := object[key]
		if !exists || string(bytesTrimSpace(raw)) == "null" {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("%s: %s must be a string", operation, key)
		}
		return value, nil
	}
	return "", nil
}

func stringFromAny(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func bytesTrimSpace(b []byte) []byte {
	return bytes.TrimSpace(b)
}

// RemainingCredits returns monthlyLimit - used (floored at 0).
func (m *MonthlyBilling) RemainingCredits() float64 {
	if m == nil {
		return 0
	}
	if m.MonthlyLimit == nil || m.Used == nil {
		return 0
	}
	rem := *m.MonthlyLimit - *m.Used
	if rem < 0 {
		return 0
	}
	return rem
}

// UsagePercent returns used/limit * 100. Zero limit → 0.
func (m *MonthlyBilling) UsagePercent() float64 {
	if m == nil || m.MonthlyLimit == nil || m.Used == nil || *m.MonthlyLimit <= 0 {
		return 0
	}
	return (*m.Used / *m.MonthlyLimit) * 100
}

func floatPointer(v float64) *float64 { return &v }
func cloneRawMap(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}
func normalizeGrokBuild(weekly *WeeklyCredits) GrokBuildQuota {
	view := GrokBuildQuota{Note: "Grok Build 产品百分比表示其对共享周额度池的消耗贡献，不是独立上限。"}
	if weekly == nil {
		return view
	}
	view.SharedWeeklyUsagePercent = weekly.CreditUsagePercent
	view.Reported = weekly.CreditUsagePercent != nil
	view.PeriodEnd = weekly.BillingPeriodEnd
	for _, product := range weekly.ProductUsage {
		if isGrokBuildProduct(product.Product) {
			view.GrokBuildContribution = product.UsagePercent
			break
		}
	}
	return view
}

func isGrokBuildProduct(name string) bool {
	return strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(name), " ", ""), "grokbuild")
}
func safeBillingError(err error) string {
	if err == nil {
		return ""
	}
	return truncate(err.Error(), 256)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
