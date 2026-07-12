// Package notify sends optional operator notifications.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/inspection"
)

type FeishuWebhookNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewFeishuWebhookNotifier(webhookURL string, client *http.Client) *FeishuWebhookNotifier {
	if strings.TrimSpace(webhookURL) == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &FeishuWebhookNotifier{webhookURL: strings.TrimSpace(webhookURL), client: client}
}

func (n *FeishuWebhookNotifier) NotifyInspection(ctx context.Context, summary inspection.Summary) error {
	if n == nil || n.webhookURL == "" {
		return nil
	}
	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]string{"text": fmt.Sprintf(
			"GrokBuild 凭证巡检完成\n检测: %d\n正常: %d\n限流/额度: %d\n认证失效: %d\n隔离: %d\n跳过: %d\n错误: %d\n完成时间: %s",
			summary.Inspected, summary.Healthy, summary.RateLimited, summary.Unauthorized,
			summary.Quarantined, summary.Skipped, summary.Errors, summary.FinishedAt.Local().Format(time.DateTime),
		)},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("feishu webhook returned http %d", resp.StatusCode)
	}
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode feishu webhook response: %w", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("feishu webhook rejected notification: code=%d msg=%s", result.Code, result.Msg)
	}
	return nil
}
