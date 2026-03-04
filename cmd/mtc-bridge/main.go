// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-bridge is the main entry point for the MTC Bridge service.
//
// It wires together all components: config loading, database connections,
// watcher, tlog-tiles HTTP API, and admin dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/acme"
	"github.com/briantrzupek/ca-extension-merkle/internal/admin"
	"github.com/briantrzupek/ca-extension-merkle/internal/assertionissuer"
	"github.com/briantrzupek/ca-extension-merkle/internal/cadb"
	"github.com/briantrzupek/ca-extension-merkle/internal/config"
	"github.com/briantrzupek/ca-extension-merkle/internal/cosigner"
	"github.com/briantrzupek/ca-extension-merkle/internal/issuancelog"
	"github.com/briantrzupek/ca-extension-merkle/internal/localca"
	"github.com/briantrzupek/ca-extension-merkle/internal/revocation"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
	"github.com/briantrzupek/ca-extension-merkle/internal/tlogtiles"
	"github.com/briantrzupek/ca-extension-merkle/internal/watcher"
)

func main() {
	configFile := flag.String("config", "config.yaml", "path to configuration file")
	generateKey := flag.String("generate-key", "", "generate a new Ed25519 key and exit")
	generateLocalCA := flag.Bool("generate-local-ca", false, "generate a self-signed local CA key + cert and exit")
	flag.Parse()

	// Key generation mode.
	if *generateKey != "" {
		pub, err := cosigner.GenerateKey(*generateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated Ed25519 key pair.\n")
		fmt.Printf("Public key (hex): %x\n", pub)
		fmt.Printf("Private key saved to: %s\n", *generateKey)
		return
	}

	// Local CA generation mode.
	if *generateLocalCA {
		keyFile := "keys/local-ca.key"
		certFile := "keys/local-ca.pem"
		if err := os.MkdirAll("keys", 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating keys directory: %v\n", err)
			os.Exit(1)
		}
		if err := localca.GenerateCA(keyFile, certFile, "MTC Demo CA", "US"); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated local CA key pair.\n")
		fmt.Printf("Private key: %s\n", keyFile)
		fmt.Printf("Certificate: %s\n", certFile)
		return
	}

	// Load configuration.
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Set up structured logging.
	logLevel := config.ParseLogLevel(cfg.Logging.Level)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("mtc-bridge starting",
		"version", "0.1.0",
		"config", *configFile,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL state store.
	stateStore, err := store.New(ctx, cfg.StateDB, logger.With("component", "store"))
	if err != nil {
		logger.Error("failed to connect to state store", "error", err)
		os.Exit(1)
	}
	defer stateStore.Close()
	logger.Info("connected to state store")

	// Run migrations.
	if err := stateStore.Migrate(ctx); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}

	// Connect to CA MariaDB database.
	caAdapter, err := cadb.New(ctx, cfg.CADB, logger.With("component", "cadb"))
	if err != nil {
		logger.Error("failed to connect to CA database", "error", err)
		os.Exit(1)
	}
	defer caAdapter.Close()
	logger.Info("connected to CA database")

	// Initialize cosigner.
	cs, err := cosigner.New(cfg.Cosigner.KeyFile, cfg.Cosigner.KeyID, cfg.Log.Origin)
	if err != nil {
		logger.Error("failed to initialize cosigner", "error", err)
		os.Exit(1)
	}
	logger.Info("cosigner initialized",
		"key_id", cs.KeyID(),
		"origin", cs.Origin(),
		"public_key", cs.PublicKeyHex(),
	)

	// Create issuance log.
	ilog := issuancelog.New(stateStore, cs, cfg.Log.Origin, logger.With("component", "issuancelog"))

	// Create revocation manager.
	revMgr := revocation.New(stateStore, logger.With("component", "revocation"))

	// Create watcher.
	watcherCfg := watcher.Config{
		PollInterval:           cfg.Watcher.PollInterval,
		CheckpointInterval:     cfg.Watcher.CheckpointInterval,
		BatchSize:              cfg.Watcher.BatchSize,
		RevocationPollInterval: cfg.Watcher.RevocationPollInterval,
	}
	w := watcher.New(caAdapter, stateStore, ilog, revMgr, watcherCfg, logger.With("component", "watcher"))

	// Create assertion issuer and hook into watcher.
	issuerCfg := assertionissuer.Config{
		Enabled:            cfg.AssertionIssuer.IsEnabled(),
		BatchSize:          cfg.AssertionIssuer.BatchSize,
		Concurrency:        cfg.AssertionIssuer.Concurrency,
		StalenessThreshold: cfg.AssertionIssuer.StalenessThreshold,
	}
	for _, wh := range cfg.AssertionIssuer.Webhooks {
		issuerCfg.Webhooks = append(issuerCfg.Webhooks, assertionissuer.WebhookConfig{
			URL:     wh.URL,
			Pattern: wh.Pattern,
			Secret:  wh.Secret,
		})
	}
	issuer := assertionissuer.New(stateStore, cfg.Log.Origin, issuerCfg, logger.With("component", "assertionissuer"))
	w.OnCheckpoint(issuer.RunOnCheckpoint)
	logger.Info("assertion issuer configured",
		"enabled", issuerCfg.Enabled,
		"batch_size", issuerCfg.BatchSize,
		"concurrency", issuerCfg.Concurrency,
		"webhooks", len(issuerCfg.Webhooks),
	)

	// Build CA name map for admin visualization.
	caNameMap := make(map[string]string)
	for _, ca := range caAdapter.GetCAs() {
		caNameMap[ca.ID] = ca.Name
	}

	// Create HTTP handlers.
	tlogHandler := tlogtiles.New(stateStore, revMgr, cfg.Log.Origin, logger.With("component", "tlogtiles"))
	adminHandler, err := admin.New(stateStore, w, issuer, cfg.Log.Origin, caNameMap, logger.With("component", "admin"))
	if err != nil {
		logger.Error("failed to create admin handler", "error", err)
		os.Exit(1)
	}

	// Optionally start ACME server.
	if cfg.ACME.Enabled {
		acmeCfg := acme.Config{
			ExternalURL:           cfg.ACME.ExternalURL,
			CAProxyURL:            cfg.ACME.CAURL,
			CAAPIKey:              cfg.ACME.CAAPIKey,
			CAID:                  cfg.ACME.CAID,
			TemplateID:            cfg.ACME.TemplateID,
			MTCBridgeURL:          cfg.ACME.MTCBridgeURL,
			OrderExpiry:           cfg.ACME.OrderExpiry,
			AssertionTimeout:      cfg.ACME.AssertionTimeout,
			AssertionPollInterval: cfg.ACME.AssertionPollInterval,
			AutoApproveChallenge:  cfg.ACME.AutoApproveChallenge,
			MTCMode:               cfg.LocalCA.MTCMode,
		}

		// Optionally initialize local CA for embedded proof issuance.
		var lca *localca.LocalCA
		if cfg.LocalCA.Enabled {
			lca, err = localca.New(localca.Config{
				KeyFile:      cfg.LocalCA.KeyFile,
				CertFile:     cfg.LocalCA.CertFile,
				Validity:     cfg.LocalCA.Validity,
				Organization: cfg.LocalCA.Organization,
				Country:      cfg.LocalCA.Country,
			})
			if err != nil {
				logger.Error("failed to initialize local CA", "error", err)
				os.Exit(1)
			}
			logger.Info("local CA initialized for embedded proof issuance",
				"key_file", cfg.LocalCA.KeyFile,
				"cert_file", cfg.LocalCA.CertFile,
			)
		}

		acmeSrv := acme.New(stateStore, acmeCfg, logger.With("component", "acme"), lca, ilog)
		acmeServer := &http.Server{
			Addr:         cfg.ACME.Addr,
			Handler:      acmeSrv,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
			BaseContext:  func(_ net.Listener) context.Context { return ctx },
		}
		go func() {
			logger.Info("ACME server starting", "addr", cfg.ACME.Addr, "external_url", cfg.ACME.ExternalURL)
			if cfg.ACME.TLSCert != "" && cfg.ACME.TLSKey != "" {
				logger.Info("ACME server using HTTPS", "cert", cfg.ACME.TLSCert, "key", cfg.ACME.TLSKey)
				if err := acmeServer.ListenAndServeTLS(cfg.ACME.TLSCert, cfg.ACME.TLSKey); err != http.ErrServerClosed {
					logger.Error("ACME server TLS error", "error", err)
				}
			} else {
				if err := acmeServer.ListenAndServe(); err != http.ErrServerClosed {
					logger.Error("ACME server error", "error", err)
				}
			}
		}()
		// Shutdown ACME server on context cancel.
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			acmeServer.Shutdown(shutdownCtx)
		}()
		logger.Info("ACME server configured",
			"addr", cfg.ACME.Addr,
			"auto_approve", cfg.ACME.AutoApproveChallenge,
			"ca_url", cfg.ACME.CAURL,
		)
	}

	// Build HTTP mux.
	mux := http.NewServeMux()
	mux.Handle("/checkpoint", tlogHandler)
	mux.Handle("/tile/", tlogHandler)
	mux.Handle("/revocation", tlogHandler)
	mux.Handle("/proof/", tlogHandler)
	mux.Handle("/assertion/", tlogHandler)
	mux.Handle("/assertions/", tlogHandler)
	mux.Handle("/admin", adminHandler)
	mux.Handle("/admin/", adminHandler)

	// Health check endpoint.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
	})

	server := &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	// Start watcher in background.
	go func() {
		if err := w.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("watcher error", "error", err)
		}
	}()

	// Start HTTP server in background.
	go func() {
		logger.Info("HTTP server starting", "addr", cfg.HTTP.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	// Wait for shutdown signal.
	<-ctx.Done()
	logger.Info("shutdown signal received")

	// Graceful shutdown with timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	logger.Info("mtc-bridge stopped")
}
