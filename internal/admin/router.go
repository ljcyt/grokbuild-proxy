package admin

import (
	"net/http"
	"strings"
)

// Handler returns an http.Handler serving all /admin routes with admin auth.
// Paths are expected without a host; the handler accepts both /admin/... and
// stripped paths when mounted under /admin/.
func (h *Handlers) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return h.RequireAdmin(mux)
}

// Register attaches admin routes on mux using Go 1.22 method patterns.
func (h *Handlers) Register(mux *http.ServeMux) {
	if mux == nil || h == nil {
		return
	}

	// Credentials collection
	mux.HandleFunc("GET /admin/credentials", h.ListCredentials)
	mux.HandleFunc("POST /admin/credentials", h.CreateCredential)
	mux.HandleFunc("POST /admin/credentials/import-grok", h.ImportGrok)
	mux.HandleFunc("POST /admin/oauth/device/start", h.StartDeviceLogin)
	mux.HandleFunc("POST /admin/oauth/device/poll", h.PollDeviceLogin)
	mux.HandleFunc("GET /admin/settings", h.RuntimeSettings)
	mux.HandleFunc("PUT /admin/settings", h.UpdateRuntimeSettings)
	mux.HandleFunc("POST /admin/import-jobs", h.StartImportJob)
	mux.HandleFunc("GET /admin/import-jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.ImportJob(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("POST /admin/credential-imports", h.StartImportJob)
	mux.HandleFunc("GET /admin/credential-imports/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.ImportJob(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("GET /admin/inspection", h.InspectionStatus)
	mux.HandleFunc("POST /admin/inspection/run", h.RunInspection)

	// Credential by id
	mux.HandleFunc("POST /admin/credentials/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		h.DisableCredential(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("PUT /admin/credentials/{id}/priority", func(w http.ResponseWriter, r *http.Request) {
		h.SetPriority(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("PUT /admin/credentials/{id}/proxy", func(w http.ResponseWriter, r *http.Request) {
		h.SetCredentialProxy(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("POST /admin/credentials/{id}/refresh", func(w http.ResponseWriter, r *http.Request) {
		h.RefreshCredential(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("GET /admin/credentials/{id}/billing", func(w http.ResponseWriter, r *http.Request) {
		h.CredentialBilling(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("DELETE /admin/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.DeleteCredential(w, r, r.PathValue("id"))
	})

	// Clients
	mux.HandleFunc("GET /admin/clients", h.ListClients)
	mux.HandleFunc("POST /admin/clients", h.CreateClient)
	mux.HandleFunc("DELETE /admin/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.DeleteClient(w, r, r.PathValue("id"))
	})

	// System
	mux.HandleFunc("GET /admin/system", h.System)

	// Fallback for non-pattern muxes / unexpected method combos.
	mux.HandleFunc("/admin/", h.dispatchFallback)
}

// dispatchFallback handles /admin/* when method+pattern routes did not match,
// using manual path parsing (also covers HEAD etc.).
func (h *Handlers) dispatchFallback(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = r.URL.Path
	}

	switch {
	case path == "/admin/credentials" && r.Method == http.MethodGet:
		h.ListCredentials(w, r)
	case path == "/admin/credentials" && r.Method == http.MethodPost:
		h.CreateCredential(w, r)
	case path == "/admin/credentials/import-grok" && r.Method == http.MethodPost:
		h.ImportGrok(w, r)
	case path == "/admin/oauth/device/start" && r.Method == http.MethodPost:
		h.StartDeviceLogin(w, r)
	case path == "/admin/oauth/device/poll" && r.Method == http.MethodPost:
		h.PollDeviceLogin(w, r)
	case path == "/admin/settings" && r.Method == http.MethodGet:
		h.RuntimeSettings(w, r)
	case path == "/admin/settings" && r.Method == http.MethodPut:
		h.UpdateRuntimeSettings(w, r)
	case path == "/admin/import-jobs" && r.Method == http.MethodPost:
		h.StartImportJob(w, r)
	case path == "/admin/credential-imports" && r.Method == http.MethodPost:
		h.StartImportJob(w, r)
	case path == "/admin/inspection" && r.Method == http.MethodGet:
		h.InspectionStatus(w, r)
	case path == "/admin/inspection/run" && r.Method == http.MethodPost:
		h.RunInspection(w, r)
	case path == "/admin/clients" && r.Method == http.MethodGet:
		h.ListClients(w, r)
	case path == "/admin/clients" && r.Method == http.MethodPost:
		h.CreateClient(w, r)
	case path == "/admin/system" && r.Method == http.MethodGet:
		h.System(w, r)
	default:
		// /admin/credentials/{id}/...
		if id, rest, ok := cutAfterPrefix(path, "/admin/credentials/"); ok {
			switch {
			case rest == "disable" && r.Method == http.MethodPost:
				h.DisableCredential(w, r, id)
				return
			case rest == "priority" && r.Method == http.MethodPut:
				h.SetPriority(w, r, id)
				return
			case rest == "proxy" && r.Method == http.MethodPut:
				h.SetCredentialProxy(w, r, id)
				return
			case rest == "refresh" && r.Method == http.MethodPost:
				h.RefreshCredential(w, r, id)
				return
			case rest == "billing" && r.Method == http.MethodGet:
				h.CredentialBilling(w, r, id)
				return
			case rest == "" && r.Method == http.MethodDelete:
				h.DeleteCredential(w, r, id)
				return
			}
		}
		if id, rest, ok := cutAfterPrefix(path, "/admin/clients/"); ok {
			if rest == "" && r.Method == http.MethodDelete {
				h.DeleteClient(w, r, id)
				return
			}
		}
		if id, rest, ok := cutAfterPrefix(path, "/admin/import-jobs/"); ok {
			if rest == "" && r.Method == http.MethodGet {
				h.ImportJob(w, r, id)
				return
			}
		}
		if id, rest, ok := cutAfterPrefix(path, "/admin/credential-imports/"); ok {
			if rest == "" && r.Method == http.MethodGet {
				h.ImportJob(w, r, id)
				return
			}
		}
		writeErr(w, http.StatusNotFound, "admin route not found")
	}
}

// cutAfterPrefix splits /prefix/{id}/rest → id, rest.
func cutAfterPrefix(path, prefix string) (id, rest string, ok bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rem := strings.TrimPrefix(path, prefix)
	if rem == "" {
		return "", "", false
	}
	if i := strings.IndexByte(rem, '/'); i >= 0 {
		return rem[:i], strings.TrimPrefix(rem[i+1:], "/"), true
	}
	return rem, "", true
}
