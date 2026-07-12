package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/inspection"
)

func TestFeishuWebhookNotifierPostsSummary(t *testing.T) {
	var payload struct {
		MsgType string `json:"msg_type"`
		Content struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	t.Cleanup(srv.Close)
	n := NewFeishuWebhookNotifier(srv.URL, srv.Client())
	if err := n.NotifyInspection(context.Background(), inspection.Summary{Inspected: 5, FinishedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if payload.MsgType != "text" || !strings.Contains(payload.Content.Text, "检测: 5") {
		t.Fatalf("payload=%+v", payload)
	}
}
