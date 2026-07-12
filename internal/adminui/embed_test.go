package adminui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedStaticFilesPresent(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		b, err := ReadStatic(name)
		if err != nil {
			t.Fatalf("missing embed static/%s: %v", name, err)
		}
		if len(b) == 0 {
			t.Fatalf("static/%s is empty", name)
		}
	}
}

func TestBillingDiagnosticsPreserveMissingValues(t *testing.T) {
	app, err := ReadStatic("app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(app)
	for _, marker := range []string{
		"var limit = optionalNum(m.monthlyLimit)",
		"var weekPct = optionalNum(w.creditUsagePercent)",
		`u.used != null ? fmtNum(u.used) : "未报告"`,
		`u.weekPct != null ? u.weekPct.toFixed(1) + "%" : "未报告"`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("app.js missing billing null-preservation marker %q", marker)
		}
	}
}

func TestCredentialCardsExposeInspectionResult(t *testing.T) {
	app, err := ReadStatic("app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(app)
	for _, marker := range []string{
		"c.last_inspection_at",
		"c.last_inspection_status",
		"c.last_inspection_error",
		`lineMeta("最近巡检"`,
		`lineMeta("巡检结果"`,
		`lineMeta("巡检详情"`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("app.js missing credential inspection marker %q", marker)
		}
	}
}

func TestCredentialListUsesPaginationWithoutBillingFanout(t *testing.T) {
	app, err := ReadStatic("app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(app)
	for _, marker := range []string{
		"function renderCredentialList()",
		"function renderCredentialPagination(pagination)",
		"&page_size=24&status=",
		"额度在查看账单时按需加载",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("app.js missing multi-account list marker %q", marker)
		}
	}
	if strings.Contains(source, "fillCredentialUsage") {
		t.Fatal("credential list must not fetch billing for every rendered card")
	}
}

func TestIndexHandlerServesHTMLWithoutAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	IndexHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type=%q want text/html", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q want no-store", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "grokbuild 管理后台") && !strings.Contains(body, "grokbuild Admin") {
		t.Fatalf("body missing title marker")
	}
	if !strings.Contains(body, "/admin/ui/app.js") {
		t.Fatalf("body missing app.js reference")
	}
}

func TestIndexHandlerHEAD(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "/admin/", nil)
	rec := httptest.NewRecorder()
	ServeIndex(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD should not write body, got %d bytes", rec.Body.Len())
	}
}

func TestAssetsHandlerServesJSAndCSS(t *testing.T) {
	h := http.StripPrefix("/admin/ui/", AssetsHandler())

	for _, path := range []string{"/admin/ui/app.js", "/admin/ui/app.css"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("%s empty body", path)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s missing nosniff", path)
		}
	}
}

func TestAssetsHandlerNotFound(t *testing.T) {
	h := http.StripPrefix("/admin/ui/", AssetsHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ui/nope.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", rec.Code)
	}
}

func TestAssetsDoNotServeIndexAsCredentials(t *testing.T) {
	// Ensure index content is not served under a credentials-like asset path.
	h := http.StripPrefix("/admin/ui/", AssetsHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ui/credentials", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		if strings.Contains(string(body), "<!DOCTYPE html>") {
			t.Fatal("credentials path must not return SPA HTML")
		}
	}
}

func TestHandlerConvenienceMux(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}
