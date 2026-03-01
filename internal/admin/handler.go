// Package admin implements the HTMX-powered admin dashboard for mtc-bridge.
//
// It provides a web UI showing log statistics, recent events, checkpoints,
// and real-time updates via Server-Sent Events (SSE).
package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"math/bits"

	"github.com/briantrzupek/ca-extension-merkle/internal/assertion"
	"github.com/briantrzupek/ca-extension-merkle/internal/assertionissuer"
	"github.com/briantrzupek/ca-extension-merkle/internal/certutil"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
	"github.com/briantrzupek/ca-extension-merkle/internal/watcher"
)

// Handler serves the admin dashboard.
type Handler struct {
	store     *store.Store
	watcher   *watcher.Watcher
	issuer    *assertionissuer.Issuer
	assertBld *assertion.Builder
	logger    *slog.Logger
	tmpl      *template.Template
	mux       *http.ServeMux
	caNames   map[string]string
}

// New creates a new admin Handler.
func New(s *store.Store, w *watcher.Watcher, iss *assertionissuer.Issuer, logOrigin string, caNames map[string]string, logger *slog.Logger) (*Handler, error) {
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
		store:     s,
		watcher:   w,
		issuer:    iss,
		assertBld: assertion.NewBuilder(s, logOrigin),
		logger:    logger,
		tmpl:      tmpl,
		mux:       http.NewServeMux(),
		caNames:   caNames,
	}

	h.mux.HandleFunc("GET /admin", h.handleDashboard)
	h.mux.HandleFunc("GET /admin/", h.handleDashboard)
	h.mux.HandleFunc("GET /admin/stats", h.handleStats)
	h.mux.HandleFunc("GET /admin/events", h.handleEvents)
	h.mux.HandleFunc("GET /admin/checkpoints", h.handleCheckpoints)
	h.mux.HandleFunc("GET /admin/sse", h.handleSSE)
	h.mux.HandleFunc("GET /admin/certs", h.handleCerts)
	h.mux.HandleFunc("GET /admin/certs/search", h.handleCertSearch)
	h.mux.HandleFunc("GET /admin/certs/{index}", h.handleCertDetail)
	h.mux.HandleFunc("GET /admin/viz", h.handleVisualization)
	h.mux.HandleFunc("GET /admin/viz/summary", h.handleVizSummary)
	h.mux.HandleFunc("GET /admin/viz/certificates", h.handleVizCertificates)
	h.mux.HandleFunc("GET /admin/viz/revocations", h.handleVizRevocations)
	h.mux.HandleFunc("GET /admin/viz/stats", h.handleVizStats)
	h.mux.HandleFunc("GET /admin/viz/proof/{index}", h.handleVizProof)
	h.mux.HandleFunc("GET /admin/viz/cert-info/{index}", h.handleVizCertInfo)

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

	assertionStats, err := h.store.GetAssertionStats(r.Context())
	if err != nil {
		h.logger.Error("admin: get assertion stats", "error", err)
		assertionStats = &store.AssertionStats{}
	}
	issuerStats := h.issuer.GetStats()

	data := map[string]interface{}{
		"Stats":          stats,
		"Events":         events,
		"Checkpoints":    checkpoints,
		"WatcherStats":   watcherStats,
		"AssertionStats": assertionStats,
		"IssuerStats":    issuerStats,
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

	assertionStats, _ := h.store.GetAssertionStats(r.Context())
	if assertionStats == nil {
		assertionStats = &store.AssertionStats{}
	}
	issuerStats := h.issuer.GetStats()

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

	lastGenerated := "never"
	if !assertionStats.LastGenerated.IsZero() && assertionStats.LastGenerated.Year() > 1970 {
		lastGenerated = assertionStats.LastGenerated.Format("2006-01-02 15:04:05 UTC")
	}

	lastRun := "never"
	if !issuerStats.LastRunTime.IsZero() {
		lastRun = issuerStats.LastRunDuration
	}

	fmt.Fprintf(w, `<h2 class="text-lg font-semibold mb-4">Log Statistics</h2>
		<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-6">
			<div><p class="text-gray-500 text-sm">Tree Size</p><p class="text-2xl font-bold">%d</p></div>
			<div><p class="text-gray-500 text-sm">Revocations</p><p class="text-2xl font-bold">%d</p></div>
			<div><p class="text-gray-500 text-sm">Checkpoints</p><p class="text-2xl font-bold">%d</p></div>
			<div><p class="text-gray-500 text-sm">Watcher</p><p class="text-2xl font-bold"><span class="%s">%s</span></p></div>
			<div><p class="text-gray-500 text-sm">Certs Processed</p><p class="text-2xl font-bold">%d</p></div>
			<div><p class="text-gray-500 text-sm">Latest Checkpoint</p><p class="text-sm font-medium mt-1">%s</p></div>
		</div>
		<h2 class="text-lg font-semibold mb-4 mt-6">Assertion Issuer</h2>
		<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-6">
			<div><p class="text-gray-500 text-sm">Total Bundles</p><p class="text-2xl font-bold">%d</p></div>
			<div><p class="text-gray-500 text-sm">Fresh</p><p class="text-2xl font-bold text-green-600">%d</p></div>
			<div><p class="text-gray-500 text-sm">Stale</p><p class="text-2xl font-bold text-amber-600">%d</p></div>
			<div><p class="text-gray-500 text-sm">Pending</p><p class="text-2xl font-bold text-blue-600">%d</p></div>
			<div><p class="text-gray-500 text-sm">Last Generated</p><p class="text-sm font-medium mt-1">%s</p></div>
			<div><p class="text-gray-500 text-sm">Last Run</p><p class="text-sm font-medium mt-1">%s</p></div>
		</div>`,
		stats.TreeSize,
		stats.RevocationCount,
		stats.CheckpointCount,
		watcherStatusClass, watcherStatusText,
		watcherStats.CertsProcessed,
		latestCheckpoint,
		assertionStats.TotalBundles,
		assertionStats.FreshBundles,
		assertionStats.StaleBundles,
		assertionStats.PendingEntries,
		lastGenerated,
		lastRun,
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

// handleCerts serves the certificate browser page.
func (h *Handler) handleCerts(w http.ResponseWriter, r *http.Request) {
	entries, err := h.store.RecentEntries(r.Context(), 50)
	if err != nil {
		h.logger.Error("admin: recent entries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, certBrowserHTML)

	// Render initial table rows inline.
	fmt.Fprint(w, `<script>document.addEventListener("DOMContentLoaded",function(){`)
	fmt.Fprint(w, `document.getElementById("cert-results").innerHTML = "`)
	for _, e := range entries {
		statusBadge := `<span class='px-2 py-0.5 rounded bg-green-100 text-green-800 text-xs'>Active</span>`
		if e.Revoked {
			statusBadge = `<span class='px-2 py-0.5 rounded bg-red-100 text-red-800 text-xs'>Revoked</span>`
		}
		serial := e.SerialHex
		if len(serial) > 24 {
			serial = serial[:24] + "..."
		}
		fmt.Fprintf(w, `<tr class='border-b hover:bg-gray-50 cursor-pointer' onclick='window.location=\\"/admin/certs/%d\\"\'>`+
			`<td class='px-3 py-2 text-sm'>%d</td>`+
			`<td class='px-3 py-2 font-mono text-xs'>%s</td>`+
			`<td class='px-3 py-2 text-xs text-gray-500'>%s</td>`+
			`<td class='px-3 py-2'>%s</td></tr>`,
			e.Index, e.Index, serial,
			e.CreatedAt.Format("2006-01-02 15:04:05"),
			statusBadge)
	}
	fmt.Fprint(w, `"});</script>`)
	fmt.Fprint(w, `</body></html>`)
}

// handleCertSearch handles HTMX search requests for certificates.
func (h *Handler) handleCertSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	status := r.URL.Query().Get("status")

	var entries []*store.SearchResult
	var err error

	switch status {
	case "revoked":
		entries, err = h.store.RevokedEntries(r.Context(), query, 50)
	default:
		if query == "" {
			entries, err = h.store.RecentEntries(r.Context(), 50)
		} else {
			entries, err = h.store.SearchEntries(r.Context(), query, 50)
		}
	}

	if err != nil {
		h.logger.Error("admin: cert search", "error", err, "query", query)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if len(entries) == 0 {
		fmt.Fprint(w, `<tr><td colspan="4" class="px-3 py-8 text-center text-gray-400">No results found</td></tr>`)
		return
	}

	for _, e := range entries {
		statusBadge := `<span class="px-2 py-0.5 rounded bg-green-100 text-green-800 text-xs">Active</span>`
		if e.Revoked {
			statusBadge = `<span class="px-2 py-0.5 rounded bg-red-100 text-red-800 text-xs">Revoked</span>`
		}
		serial := e.SerialHex
		if len(serial) > 24 {
			serial = serial[:24] + "..."
		}
		fmt.Fprintf(w, `<tr class="border-b hover:bg-gray-50 cursor-pointer" onclick="window.location='/admin/certs/%d'">
			<td class="px-3 py-2 text-sm">%d</td>
			<td class="px-3 py-2 font-mono text-xs">%s</td>
			<td class="px-3 py-2 text-xs text-gray-500">%s</td>
			<td class="px-3 py-2">%s</td>
		</tr>`,
			e.Index, e.Index, serial,
			e.CreatedAt.Format("2006-01-02 15:04:05"),
			statusBadge)
	}
}

// handleCertDetail shows a certificate detail page with assertion bundle.
func (h *Handler) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	indexStr := r.PathValue("index")
	idx, err := strconv.ParseInt(indexStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	bundle, err := h.assertBld.BuildByIndex(r.Context(), idx)
	if err != nil {
		h.logger.Error("admin: cert detail", "error", err, "index", idx)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Parse the certificate for display.
	var certMeta *certutil.CertMeta
	var certPEM string
	if bundle.CertDER != nil {
		certMeta = bundle.CertMeta
		block := &pem.Block{Type: "CERTIFICATE", Bytes: bundle.CertDER}
		certPEM = string(pem.EncodeToMemory(block))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, certDetailStartHTML, idx)

	// Two-column layout: info cards on left, actions sidebar on right.
	fmt.Fprint(w, `<div class="grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-6 mb-6">`)

	// Left column: info cards.
	fmt.Fprint(w, `<div class="space-y-6">`)

	// Certificate Info card.
	if certMeta != nil {
		fmt.Fprint(w, `<div class="bg-white rounded-lg shadow p-6">`)
		fmt.Fprint(w, `<h2 class="text-lg font-semibold mb-4">Certificate Details</h2>`)
		fmt.Fprint(w, `<dl class="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">`)
		certField(w, "Common Name", certMeta.CommonName)
		if len(certMeta.Organization) > 0 {
			certField(w, "Organization", certMeta.Organization[0])
		}
		certField(w, "Serial Number", certMeta.SerialNumber)
		certField(w, "Not Before", certMeta.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		certField(w, "Not After", certMeta.NotAfter.Format("2006-01-02 15:04:05 UTC"))
		certField(w, "Key Algorithm", certMeta.KeyAlgorithm)
		certField(w, "Signature Algorithm", certMeta.SignatureAlgorithm)
		certField(w, "Issuer CN", certMeta.IssuerCN)
		if certMeta.KeyUsage != "" {
			certField(w, "Key Usage", certMeta.KeyUsage)
		}
		if len(certMeta.SANs) > 0 {
			for i, san := range certMeta.SANs {
				if i == 0 {
					certField(w, "SANs", san)
				} else {
					certField(w, "", san)
				}
			}
		}
		fmt.Fprint(w, `</dl></div>`)
	}

	// Revocation status.
	if bundle.Revoked {
		revokedAt := "unknown"
		if bundle.RevokedAt != nil {
			revokedAt = bundle.RevokedAt.Format("2006-01-02 15:04:05 UTC")
		}
		fmt.Fprintf(w, `<div class="bg-red-50 border border-red-200 rounded-lg p-4">
			<span class="font-semibold text-red-800">Certificate Revoked</span>
			<span class="text-sm text-red-600 ml-2">at %s</span>
		</div>`, revokedAt)
	}

	// Inclusion proof card.
	fmt.Fprint(w, `<div class="bg-white rounded-lg shadow p-6">`)
	fmt.Fprint(w, `<h2 class="text-lg font-semibold mb-4">Merkle Inclusion Proof</h2>`)
	fmt.Fprint(w, `<dl class="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">`)
	certField(w, "Leaf Index", fmt.Sprintf("%d", bundle.LeafIndex))
	certField(w, "Tree Size", fmt.Sprintf("%d", bundle.TreeSize))
	certField(w, "Leaf Hash", truncateHash(bundle.LeafHash))
	certField(w, "Root Hash", truncateHash(bundle.RootHash))
	certField(w, "Proof Length", fmt.Sprintf("%d hashes", len(bundle.Proof)))
	fmt.Fprint(w, `</dl>`)

	// Proof hashes.
	if len(bundle.Proof) > 0 {
		fmt.Fprint(w, `<details class="mt-4"><summary class="cursor-pointer text-sm text-indigo-600">Show proof hashes</summary>`)
		fmt.Fprint(w, `<ol class="mt-2 font-mono text-xs space-y-1 list-decimal list-inside">`)
		for _, ph := range bundle.Proof {
			fmt.Fprintf(w, `<li>%s</li>`, ph)
		}
		fmt.Fprint(w, `</ol></details>`)
	}
	fmt.Fprint(w, `</div>`)

	fmt.Fprint(w, `</div>`) // end left column

	// Right column: actions sidebar.
	fmt.Fprint(w, `<div class="space-y-4 lg:sticky lg:top-8 lg:self-start">`)

	// Download section.
	fmt.Fprint(w, `<div class="bg-white rounded-lg shadow p-5">`)
	fmt.Fprint(w, `<h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">Download</h3>`)
	fmt.Fprintf(w, `<div class="flex flex-col gap-2">
		<a href="/assertion/%d" class="block text-center px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 text-sm">JSON Bundle</a>
		<a href="/assertion/%d/pem" class="block text-center px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 text-sm">PEM Bundle</a>
	</div>`, idx, idx)
	fmt.Fprint(w, `</div>`)

	// Visualize section.
	fmt.Fprint(w, `<div class="bg-white rounded-lg shadow p-5">`)
	fmt.Fprint(w, `<h3 class="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">Visualize</h3>`)
	fmt.Fprintf(w, `<div class="flex flex-col gap-2">
		<a href="/admin/viz?tab=proof&index=%d" class="block text-center px-4 py-2 border border-indigo-600 text-indigo-600 rounded hover:bg-indigo-50 text-sm">Proof Explorer</a>
		<a href="/admin/viz?tab=sunburst&index=%d" class="block text-center px-4 py-2 border border-indigo-600 text-indigo-600 rounded hover:bg-indigo-50 text-sm">Sunburst</a>
		<a href="/admin/viz?tab=treemap&index=%d" class="block text-center px-4 py-2 border border-indigo-600 text-indigo-600 rounded hover:bg-indigo-50 text-sm">Treemap</a>
	</div>`, idx, idx, idx)
	fmt.Fprint(w, `</div>`)

	fmt.Fprint(w, `</div>`) // end right column
	fmt.Fprint(w, `</div>`) // end grid

	// Certificate PEM.
	if certPEM != "" {
		fmt.Fprint(w, `<div class="bg-white rounded-lg shadow p-6 mb-6">`)
		fmt.Fprint(w, `<h2 class="text-lg font-semibold mb-4">Certificate PEM</h2>`)
		fmt.Fprintf(w, `<pre class="bg-gray-50 p-4 rounded text-xs font-mono overflow-x-auto">%s</pre>`, certPEM)
		fmt.Fprint(w, `</div>`)
	}

	fmt.Fprint(w, certDetailEndHTML)
}

func certField(w http.ResponseWriter, label, value string) {
	if label != "" {
		fmt.Fprintf(w, `<dt class="text-gray-500">%s</dt>`, label)
	} else {
		fmt.Fprint(w, `<dt></dt>`)
	}
	fmt.Fprintf(w, `<dd class="font-mono">%s</dd>`, value)
}

func truncateHash(h string) string {
	if len(h) > 32 {
		return h[:32] + "..."
	}
	return h
}

// --- Visualization Handlers ---

// handleVisualization serves the visualization explorer page.
func (h *Handler) handleVisualization(w http.ResponseWriter, r *http.Request) {
	// Trigger async metadata population on page load.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for {
			n, err := h.store.PopulateCertMetadata(ctx, h.caNames)
			if err != nil {
				h.logger.Error("admin: populate cert metadata", "error", err)
				return
			}
			if n == 0 {
				return
			}
			h.logger.Info("admin: populated cert metadata", "count", n)
		}
	}()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, vizExplorerHTML)
}

// handleVizSummary returns the aggregated certificate hierarchy as JSON.
func (h *Handler) handleVizSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := h.store.GetVizSummary(r.Context())
	if err != nil {
		h.logger.Error("admin: viz summary", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// handleVizCertificates returns paginated leaf-level certificates as JSON.
func (h *Handler) handleVizCertificates(w http.ResponseWriter, r *http.Request) {
	ca := r.URL.Query().Get("ca")
	batch := r.URL.Query().Get("batch")
	algo := r.URL.Query().Get("algo")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 500
	offset := (page - 1) * limit

	certs, total, err := h.store.GetVizCertificates(r.Context(), ca, batch, algo, limit, offset)
	if err != nil {
		h.logger.Error("admin: viz certificates", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"certificates": certs,
		"total":        total,
		"page":         page,
		"pageSize":     limit,
	})
}

// handleVizRevocations returns revoked entry indices as JSON.
func (h *Handler) handleVizRevocations(w http.ResponseWriter, r *http.Request) {
	indices, err := h.store.GetRevokedIndices(r.Context())
	if err != nil {
		h.logger.Error("admin: viz revocations", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"revokedIndices": indices,
	})
}

// handleVizStats returns aggregate visualization statistics as JSON.
func (h *Handler) handleVizStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetVizStats(r.Context())
	if err != nil {
		h.logger.Error("admin: viz stats", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleVizProof returns the Merkle inclusion proof for a given leaf index.
func (h *Handler) handleVizProof(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.ParseInt(idxStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	cp, err := h.store.LatestCheckpoint(r.Context())
	if err != nil {
		h.logger.Error("admin: viz proof: latest checkpoint", "error", err)
		http.Error(w, "no checkpoint available", http.StatusServiceUnavailable)
		return
	}

	if idx < 0 || idx >= cp.TreeSize {
		http.Error(w, fmt.Sprintf("index %d out of range [0, %d)", idx, cp.TreeSize), http.StatusBadRequest)
		return
	}

	detail, err := h.store.GetEntryDetail(r.Context(), idx)
	if err != nil {
		h.logger.Error("admin: viz proof: get entry", "error", err)
		http.Error(w, "entry not found", http.StatusNotFound)
		return
	}

	leafHash := merkle.LeafHash(detail.EntryData)

	nodeAt := func(level int, nodeIdx int64) merkle.Hash {
		nd, err := h.store.GetTreeNode(r.Context(), level, nodeIdx)
		if err != nil {
			return merkle.EmptyHash
		}
		return nd
	}

	proof, err := merkle.InclusionProofFromNodes(idx, cp.TreeSize, nodeAt)
	if err != nil {
		h.logger.Error("admin: viz proof: inclusion proof", "error", err)
		http.Error(w, "failed to compute proof", http.StatusInternalServerError)
		return
	}

	proofHex := make([]string, len(proof))
	proofSides := make([]string, len(proof))
	for i, ph := range proof {
		proofHex[i] = hex.EncodeToString(ph[:])
		// At level i of the proof, if bit i of index is 0, the sibling is on the right.
		if (idx>>uint(i))&1 == 0 {
			proofSides[i] = "right"
		} else {
			proofSides[i] = "left"
		}
	}

	treeDepth := 0
	if cp.TreeSize > 1 {
		treeDepth = bits.Len64(uint64(cp.TreeSize - 1))
	}

	resp := struct {
		LeafIndex  int64    `json:"leafIndex"`
		TreeSize   int64    `json:"treeSize"`
		LeafHash   string   `json:"leafHash"`
		RootHash   string   `json:"rootHash"`
		ProofPath  []string `json:"proofPath"`
		ProofSides []string `json:"proofSides"`
		TreeDepth  int      `json:"treeDepth"`
	}{
		LeafIndex:  idx,
		TreeSize:   cp.TreeSize,
		LeafHash:   hex.EncodeToString(leafHash[:]),
		RootHash:   hex.EncodeToString(cp.RootHash),
		ProofPath:  proofHex,
		ProofSides: proofSides,
		TreeDepth:  treeDepth,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleVizCertInfo returns a certificate's position in the visualization hierarchy.
func (h *Handler) handleVizCertInfo(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.ParseInt(idxStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	caName, batchWindow, keyAlgo, err := h.store.GetCertLocation(r.Context(), idx)
	if err != nil {
		http.Error(w, "certificate metadata not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ca":    caName,
		"batch": batchWindow.Format("Jan 2 15:04"),
		"algo":  keyAlgo,
	})
}

// Suppress unused import warnings.
var _ = hex.EncodeToString
