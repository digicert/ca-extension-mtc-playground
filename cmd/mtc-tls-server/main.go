// Command mtc-tls-server is a demo HTTPS server that staples MTC assertion
// bundles into TLS handshakes via the SignedCertificateTimestamps extension.
//
// It fetches the assertion bundle for its certificate from a running mtc-bridge
// instance and includes it in every TLS connection, allowing clients to extract
// and verify the Merkle inclusion proof inline.
//
// Usage:
//
//	go run ./cmd/mtc-tls-server -cert cert.pem -key key.pem -bridge-url http://localhost:8080
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/assertion"
)

var (
	certFile   = flag.String("cert", "cert.pem", "PEM-encoded TLS certificate")
	keyFile    = flag.String("key", "key.pem", "PEM-encoded TLS private key")
	bridgeURL  = flag.String("bridge-url", "http://localhost:8080", "mtc-bridge base URL")
	listenAddr = flag.String("addr", ":4443", "TLS listen address")
	refreshSec = flag.Int("refresh", 60, "assertion refresh interval in seconds (0 to disable)")
)

// assertionState holds the current assertion bundle and TLS certificate,
// protected by a RWMutex for concurrent access from TLS handshakes and
// the background refresh goroutine.
type assertionState struct {
	mu         sync.RWMutex
	baseCert   tls.Certificate
	leaf       *x509.Certificate
	serial     string
	bundle     *assertion.Bundle
	bundleJSON []byte
	fetchedAt  time.Time
	lastError  error
}

func (s *assertionState) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert := s.baseCert
	if s.bundleJSON != nil {
		cert.SignedCertificateTimestamps = [][]byte{s.bundleJSON}
	}
	return &cert, nil
}

// stapleBundle is a lightweight version of assertion.Bundle for SCT transport.
// It omits cert_der and cert_meta since the client already has the certificate.
type stapleBundle struct {
	LeafIndex  int64      `json:"leaf_index"`
	SerialHex  string     `json:"serial_hex,omitempty"`
	LeafHash   string     `json:"leaf_hash"`
	Proof      []string   `json:"proof"`
	TreeSize   int64      `json:"tree_size"`
	RootHash   string     `json:"root_hash"`
	Checkpoint string     `json:"checkpoint"`
	Revoked    bool       `json:"revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LogOrigin  string     `json:"log_origin"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *assertionState) fetchAssertion(bridgeBase, serial string) {
	url := strings.TrimRight(bridgeBase, "/") + "/assertion/" + serial
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		s.mu.Lock()
		s.lastError = fmt.Errorf("fetch: %w", err)
		s.mu.Unlock()
		log.Printf("WARNING: failed to fetch assertion: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		s.mu.Lock()
		s.lastError = fmt.Errorf("bridge returned %d: %s", resp.StatusCode, string(body))
		s.mu.Unlock()
		log.Printf("WARNING: assertion not available (HTTP %d)", resp.StatusCode)
		return
	}

	var bundle assertion.Bundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		s.mu.Lock()
		s.lastError = fmt.Errorf("decode: %w", err)
		s.mu.Unlock()
		log.Printf("WARNING: failed to decode assertion: %v", err)
		return
	}

	// Create lightweight staple (omit cert_der and cert_meta).
	staple := stapleBundle{
		LeafIndex:  bundle.LeafIndex,
		SerialHex:  bundle.SerialHex,
		LeafHash:   bundle.LeafHash,
		Proof:      bundle.Proof,
		TreeSize:   bundle.TreeSize,
		RootHash:   bundle.RootHash,
		Checkpoint: bundle.Checkpoint,
		Revoked:    bundle.Revoked,
		RevokedAt:  bundle.RevokedAt,
		LogOrigin:  bundle.LogOrigin,
		CreatedAt:  bundle.CreatedAt,
	}

	bundleJSON, err := json.Marshal(staple)
	if err != nil {
		s.mu.Lock()
		s.lastError = fmt.Errorf("marshal: %w", err)
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.bundle = &bundle
	s.bundleJSON = bundleJSON
	s.fetchedAt = time.Now()
	s.lastError = nil
	s.mu.Unlock()

	log.Printf("Assertion stapled: leaf=%d tree_size=%d proof_depth=%d (%d bytes)",
		bundle.LeafIndex, bundle.TreeSize, len(bundle.Proof), len(bundleJSON))
}

func (s *assertionState) refreshLoop(ctx context.Context, bridgeBase, serial string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.fetchAssertion(bridgeBase, serial)
		}
	}
}

func main() {
	flag.Parse()

	// Load TLS certificate and key.
	tlsCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading TLS cert/key: %v\n", err)
		os.Exit(1)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	serial := strings.ToUpper(hex.EncodeToString(leaf.SerialNumber.Bytes()))

	fmt.Printf("MTC TLS Server\n")
	fmt.Printf("  Subject:    %s\n", leaf.Subject.CommonName)
	fmt.Printf("  Serial:     %s\n", serial)
	fmt.Printf("  Listen:     %s\n", *listenAddr)
	fmt.Printf("  Bridge:     %s\n", *bridgeURL)
	fmt.Println()

	state := &assertionState{
		baseCert: tlsCert,
		leaf:     leaf,
		serial:   serial,
	}

	// Initial assertion fetch.
	fmt.Print("Fetching MTC assertion... ")
	state.fetchAssertion(*bridgeURL, serial)
	state.mu.RLock()
	if state.bundle != nil {
		fmt.Printf("OK (leaf=%d, tree_size=%d)\n", state.bundle.LeafIndex, state.bundle.TreeSize)
	} else {
		fmt.Printf("not available yet (will retry)\n")
	}
	state.mu.RUnlock()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start background refresh.
	if *refreshSec > 0 {
		go state.refreshLoop(ctx, *bridgeURL, serial, time.Duration(*refreshSec)*time.Second)
	}

	// HTTP handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		serveStatusPage(w, state)
	})
	mux.HandleFunc("GET /mtc-status", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		status := map[string]interface{}{
			"available": state.bundle != nil,
			"serial":    state.serial,
		}
		if state.bundle != nil {
			status["leaf_index"] = state.bundle.LeafIndex
			status["tree_size"] = state.bundle.TreeSize
			status["root_hash"] = state.bundle.RootHash
			status["proof_depth"] = len(state.bundle.Proof)
			status["revoked"] = state.bundle.Revoked
			status["log_origin"] = state.bundle.LogOrigin
			status["fetched_at"] = state.fetchedAt.Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	// TLS config.
	tlsConfig := &tls.Config{
		GetCertificate: state.getCertificate,
	}

	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("\nListening on https://localhost%s\n", *listenAddr)
	fmt.Printf("  Status page:  https://localhost%s/\n", *listenAddr)
	fmt.Printf("  JSON status:  https://localhost%s/mtc-status\n\n", *listenAddr)

	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nShutdown complete.")
}

func serveStatusPage(w http.ResponseWriter, state *assertionState) {
	leaf := state.leaf
	available := state.bundle != nil

	var assertionHTML string
	if available {
		b := state.bundle
		rootTrunc := b.RootHash
		if len(rootTrunc) > 16 {
			rootTrunc = rootTrunc[:16] + "..."
		}
		assertionHTML = fmt.Sprintf(`
        <div style="background:#065f46;border:1px solid #059669;border-radius:8px;padding:16px;margin-top:16px">
          <div style="font-size:18px;font-weight:700;color:#34d399;margin-bottom:8px">MTC Assertion Stapled</div>
          <table style="width:100%%;color:#d1fae5;font-size:14px">
            <tr><td style="padding:4px 8px;color:#6ee7b7">Leaf Index</td><td>%d</td></tr>
            <tr><td style="padding:4px 8px;color:#6ee7b7">Tree Size</td><td>%d</td></tr>
            <tr><td style="padding:4px 8px;color:#6ee7b7">Root Hash</td><td style="font-family:monospace">%s</td></tr>
            <tr><td style="padding:4px 8px;color:#6ee7b7">Proof Depth</td><td>%d sibling hashes</td></tr>
            <tr><td style="padding:4px 8px;color:#6ee7b7">Revoked</td><td>%t</td></tr>
            <tr><td style="padding:4px 8px;color:#6ee7b7">Log Origin</td><td>%s</td></tr>
          </table>
        </div>`,
			b.LeafIndex, b.TreeSize, rootTrunc, len(b.Proof), b.Revoked, b.LogOrigin)
	} else {
		assertionHTML = `
        <div style="background:#7c2d12;border:1px solid #c2410c;border-radius:8px;padding:16px;margin-top:16px">
          <div style="font-size:18px;font-weight:700;color:#fb923c">Assertion Not Available</div>
          <p style="color:#fed7aa;margin-top:8px">The MTC assertion bundle is not yet available. The server will retry periodically.</p>
        </div>`
	}

	notBefore := leaf.NotBefore.Format("2006-01-02 15:04 UTC")
	notAfter := leaf.NotAfter.Format("2006-01-02 15:04 UTC")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>MTC TLS Demo</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px;
           display: flex; justify-content: center; }
    .container { max-width: 640px; width: 100%%; }
    h1 { color: #38bdf8; font-size: 28px; margin-bottom: 4px; }
    .subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 24px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .card h2 { color: #38bdf8; font-size: 16px; margin: 0 0 12px 0; }
    table { width: 100%%; }
    td { padding: 4px 8px; font-size: 14px; }
    td:first-child { color: #94a3b8; white-space: nowrap; width: 140px; }
    .mono { font-family: "SF Mono", "Fira Code", monospace; }
    .link { color: #38bdf8; text-decoration: none; }
    .link:hover { text-decoration: underline; }
    .footer { color: #64748b; font-size: 12px; margin-top: 24px; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <h1>MTC-Verified TLS Connection</h1>
    <p class="subtitle">This connection carries a Merkle Tree Certificate assertion stapled via the TLS SCT extension.</p>

    <div class="card">
      <h2>Certificate</h2>
      <table>
        <tr><td>Subject</td><td>%s</td></tr>
        <tr><td>Serial</td><td class="mono">%s</td></tr>
        <tr><td>Issuer</td><td>%s</td></tr>
        <tr><td>Valid From</td><td>%s</td></tr>
        <tr><td>Valid To</td><td>%s</td></tr>
      </table>
    </div>

    %s

    <div class="card">
      <h2>How It Works</h2>
      <p style="font-size:13px;color:#94a3b8;line-height:1.6">
        This server fetches an MTC assertion bundle from the mtc-bridge transparency log
        and staples it to TLS handshakes using the <code style="color:#38bdf8">SignedCertificateTimestamps</code>
        extension field. Connecting clients can extract the assertion and verify the Merkle
        inclusion proof, confirming this certificate is logged in the transparency tree.
      </p>
      <p style="font-size:13px;color:#94a3b8;line-height:1.6;margin-top:8px">
        Verify with: <code style="color:#34d399">mtc-tls-verify -url https://localhost%s -insecure</code>
      </p>
    </div>

    <div class="footer">
      MTC Bridge &mdash; Phase 4 TLS Assertion Stapling Demo
    </div>
  </div>
</body>
</html>`,
		leaf.Subject.CommonName,
		state.serial,
		leaf.Issuer.CommonName,
		notBefore,
		notAfter,
		assertionHTML,
		*listenAddr,
	)
}
