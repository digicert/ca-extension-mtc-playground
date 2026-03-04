// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/issuancelog"
	"github.com/briantrzupek/ca-extension-merkle/internal/localca"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Config holds ACME server configuration.
type Config struct {
	ExternalURL           string
	CAProxyURL            string
	CAAPIKey              string
	CAID                  string
	TemplateID            string
	MTCBridgeURL          string
	OrderExpiry           time.Duration
	AssertionTimeout      time.Duration
	AssertionPollInterval time.Duration
	AutoApproveChallenge  bool
	MTCMode               bool // When true, issue MTC-spec-compliant certs (signatureless)
}

// Server is the ACME server.
type Server struct {
	store   *store.Store
	cfg     Config
	logger  *slog.Logger
	mux     *http.ServeMux
	mu      sync.Mutex
	nonces  map[string]time.Time
	localCA *localca.LocalCA   // nil = DigiCert proxy, non-nil = local CA with embedded proofs
	ilog    *issuancelog.Log   // needed for direct log append in local CA mode
}

// New creates a new ACME server. The localCA and ilog parameters are optional;
// when non-nil, the server uses the local CA for two-phase signing with embedded
// inclusion proofs instead of proxying to the DigiCert CA.
func New(s *store.Store, cfg Config, logger *slog.Logger, lca *localca.LocalCA, ilog *issuancelog.Log) *Server {
	if cfg.OrderExpiry <= 0 {
		cfg.OrderExpiry = 24 * time.Hour
	}
	if cfg.AssertionTimeout <= 0 {
		cfg.AssertionTimeout = 5 * time.Minute
	}
	if cfg.AssertionPollInterval <= 0 {
		cfg.AssertionPollInterval = 5 * time.Second
	}
	srv := &Server{
		store:   s,
		cfg:     cfg,
		logger:  logger,
		mux:     http.NewServeMux(),
		nonces:  make(map[string]time.Time),
		localCA: lca,
		ilog:    ilog,
	}
	srv.mux.HandleFunc("GET /acme/directory", srv.handleDirectory)
	srv.mux.HandleFunc("HEAD /acme/new-nonce", srv.handleNewNonce)
	srv.mux.HandleFunc("GET /acme/new-nonce", srv.handleNewNonce)
	srv.mux.HandleFunc("POST /acme/new-nonce", srv.handleNewNonce)
	srv.mux.HandleFunc("POST /acme/new-account", srv.handleNewAccount)
	srv.mux.HandleFunc("POST /acme/new-order", srv.handleNewOrder)
	srv.mux.HandleFunc("POST /acme/order/{id}", srv.handleOrder)
	srv.mux.HandleFunc("POST /acme/order/{id}/finalize", srv.handleFinalize)
	srv.mux.HandleFunc("POST /acme/authz/{id}", srv.handleAuthorization)
	srv.mux.HandleFunc("POST /acme/challenge/{id}", srv.handleChallenge)
	srv.mux.HandleFunc("POST /acme/certificate/{id}", srv.handleCertificate)
	go srv.cleanupNonces()
	return srv
}

// ServeHTTP implements http.Handler.
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", srv.newNonce())
	w.Header().Set("Content-Type", "application/json")
	srv.mux.ServeHTTP(w, r)
}
