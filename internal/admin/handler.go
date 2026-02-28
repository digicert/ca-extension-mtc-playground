// Package admin implements the HTMX-powered admin dashboard for mtc-bridge.
//
// It provides a web UI showing log statistics, recent events, checkpoints,
// and real-time updates via Server-Sent Events (SSE).
package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/store"
	"github.com/briantrzupek/ca-extension-merkle/internal/watcher"
)

// Handler serves the admin dashboard.
type Handler struct {
	store   *store.Store
	watcher *watcher.Watcher
	logger  *slog.Logger
	tmpl    *template.Template
	mux     *http.ServeMux
}

// New creates a new admin Handler.
func New(s *store.Store, w *watcher.Watcher, logger *slog.Logger) (*Handler, error) {
	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.Format("2006-01-02 15:04:05 UTC")
		},
		"formatJSON": func(data json.RawMessage) string {
			var v interface{}
			if err := json.Unmarshal(data, &v); err != nil {
				return string(data)
			}
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
		"truncHash": func(b []byte) string {
			if len(b) > 8 {
				return fmt.Sprintf("%x...", b[:8])
			}
			return fmt.Sprintf("%x", b)
		},
	}

	tmpl, err := template.New("admin").Funcs(funcMap).Parse(dashboardHTML)
	if err != nil {
		return nil, fmt.Errorf("admin.New: parse template: %w", err)
	}

	h := &Handler{
		store:   s,
		watcher: w,
		logger:  logger,
		tmpl:    tmpl,
		mux:     http.NewServeMux(),
	}

	h.mux.HandleFunc("GET /admin", h.handleDashboard)
	h.mux.HandleFunc("GET /admin/", h.handleDashboard)
	h.mux.HandleFunc("GET /admin/stats", h.handleStats)
	h.mux.HandleFunc("GET /admin/events", h.handleEvents)
	h.mux.HandleFunc("GET /admin/checkpoints", h.handleCheckpoints)
	h.mux.HandleFunc("GET /admin/sse", h.handleSSE)

	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetStats(r.Context())
	if err != nil {
		h.logger.Error("admin: get stats", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	events, err := h.store.RecentEvents(r.Context(), 20)
	if err != nil {
		h.logger.Error("admin: get events", "error", err)
		events = nil
	}

	checkpoints, err := h.store.RecentCheckpoints(r.Context(), 10)
	if err != nil {
		h.logger.Error("admin: get checkpoints", "error", err)
		checkpoints = nil
	}

	watcherStats := h.watcher.GetStats()

	data := map[string]interface{}{
		"Stats":        stats,
		"Events":       events,
		"Checkpoints":  checkpoints,
		"WatcherStats": watcherStats,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.Execute(w, data); err != nil {
		h.logger.Error("admin: render template", "error", err)
	}
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetStats(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	watcherStats := h.watcher.GetStats()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	watcherStatusClass := "text-red-600"
	watcherStatusText := "Stopped"
	if watcherStats.Running {
		watcherStatusClass = "text-green-600"
		watcherStatusText = "Running"
	}

	latestCheckpoint := "never"
	if !stats.LatestCheckpoint.IsZero() {
		latestCheckpoint = stats.LatestCheckpoint.Format("2006-01-02 15:04:05 UTC")
	}

	fmt.Fprintf(w, `<h2 class="text-lg font-semibold mb-4">Log Statistics</h2>
		<dl class="grid grid-cols-2 md:grid-cols-3 gap-4">
			<dt class="text-gray-500">Tree Size</dt>
			<dd class="text-2xl font-bold">%d</dd>
			<dt class="text-gray-500">Revocations</dt>
			<dd class="text-2xl font-bold">%d</dd>
			<dt class="text-gray-500">Checkpoints</dt>
			<dd class="text-2xl font-bold">%d</dd>
			<dt class="text-gray-500">Watcher</dt>
			<dd class="text-2xl font-bold"><span class="%s">%s</span></dd>
			<dt class="text-gray-500">Certs Processed</dt>
			<dd class="text-2xl font-bold">%d</dd>
			<dt class="text-gray-500">Latest Checkpoint</dt>
			<dd class="text-sm">%s</dd>
		</dl>`,
		stats.TreeSize,
		stats.RevocationCount,
		stats.CheckpointCount,
		watcherStatusClass, watcherStatusText,
		watcherStats.CertsProcessed,
		latestCheckpoint,
	)
}

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := h.store.RecentEvents(r.Context(), 20)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, e := range events {
		fmt.Fprintf(w, `<tr class="border-b">
			<td class="px-2 py-1 text-sm">%d</td>
			<td class="px-2 py-1"><span class="px-2 py-0.5 rounded bg-blue-100 text-blue-800 text-xs">%s</span></td>
			<td class="px-2 py-1 text-xs text-gray-500">%s</td>
		</tr>`, e.ID, e.EventType, e.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	}
}

func (h *Handler) handleCheckpoints(w http.ResponseWriter, r *http.Request) {
	checkpoints, err := h.store.RecentCheckpoints(r.Context(), 10)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, cp := range checkpoints {
		fmt.Fprintf(w, `<tr class="border-b">
			<td class="px-2 py-1 text-sm">%d</td>
			<td class="px-2 py-1 font-mono text-sm">%d</td>
			<td class="px-2 py-1 font-mono text-xs">%x...</td>
			<td class="px-2 py-1 text-xs text-gray-500">%s</td>
		</tr>`, cp.ID, cp.TreeSize, cp.RootHash[:8], cp.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	}
}

// handleSSE streams server-sent events for live dashboard updates.
func (h *Handler) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var lastEventID int64
	if idStr := r.Header.Get("Last-Event-ID"); idStr != "" {
		lastEventID, _ = strconv.ParseInt(idStr, 10, 64)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			events, err := h.store.EventsSince(r.Context(), lastEventID)
			if err != nil {
				continue
			}

			for _, e := range events {
				data, _ := json.Marshal(e)
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.EventType, data)
				lastEventID = e.ID
			}
			flusher.Flush()
		}
	}
}

func boolStatus(b bool) string {
	if b {
		return "Running"
	}
	return "Stopped"
}
