// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package config provides YAML configuration loading with environment variable
// substitution for the mtc-bridge service.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for mtc-bridge.
type Config struct {
	// Log configures the issuance log identity and parameters.
	Log LogConfig `yaml:"log"`

	// StateDB configures the PostgreSQL state store.
	StateDB PostgresConfig `yaml:"state_db"`

	// CADB configures the DigiCert CA MariaDB connection (read-only).
	CADB MariaDBConfig `yaml:"ca_db"`

	// HTTP configures the HTTP server for tile serving and admin dashboard.
	HTTP HTTPConfig `yaml:"http"`

	// Watcher configures the background CA polling loop.
	Watcher WatcherConfig `yaml:"watcher"`

	// Cosigner configures the primary signing key.
	Cosigner CosignerConfig `yaml:"cosigner"`

	// AdditionalCosigners configures extra cosigners (e.g., post-quantum ML-DSA).
	AdditionalCosigners []AdditionalCosignerConfig `yaml:"additional_cosigners"`

	// Logging configures structured logging.
	Logging LoggingConfig `yaml:"logging"`

	// AssertionIssuer configures the background assertion generation pipeline.
	AssertionIssuer AssertionIssuerConfig `yaml:"assertion_issuer"`

	// ACME configures the optional ACME server for RFC 8555 certificate issuance.
	ACME ACMEConfig `yaml:"acme"`

	// LocalCA configures the optional local intermediate CA for embedded proof issuance.
	LocalCA LocalCAConfig `yaml:"local_ca"`
}

// ACMEConfig configures the ACME server.
type ACMEConfig struct {
	// Enabled turns the ACME server on/off (default: false).
	Enabled bool `yaml:"enabled"`

	// Addr is the listen address for the ACME server (e.g., ":8443").
	Addr string `yaml:"addr"`

	// ExternalURL is the base URL clients use to reach this ACME server.
	ExternalURL string `yaml:"external_url"`

	// CAURL is the DigiCert Private CA REST API base URL.
	CAURL string `yaml:"ca_url"`

	// CAAPIKey is the DigiCert CA API key.
	CAAPIKey string `yaml:"ca_api_key"`

	// CAID is the issuing CA ID in DigiCert.
	CAID string `yaml:"ca_id"`

	// TemplateID is the certificate template ID.
	TemplateID string `yaml:"template_id"`

	// MTCBridgeURL is the base URL of the mtc-bridge for assertion lookups (e.g., "http://localhost:8080").
	MTCBridgeURL string `yaml:"mtc_bridge_url"`

	// OrderExpiry is how long an order stays valid (default: 24h).
	OrderExpiry time.Duration `yaml:"order_expiry"`

	// AssertionTimeout is how long to wait for an assertion bundle after cert issuance (default: 5m).
	AssertionTimeout time.Duration `yaml:"assertion_timeout"`

	// AssertionPollInterval is how often to poll for assertion bundles (default: 5s).
	AssertionPollInterval time.Duration `yaml:"assertion_poll_interval"`

	// AutoApproveChallenge skips real http-01 validation (for internal CAs).
	AutoApproveChallenge bool `yaml:"auto_approve_challenge"`

	// TLSCert is the path to the TLS certificate for HTTPS.
	TLSCert string `yaml:"tls_cert"`

	// TLSKey is the path to the TLS private key for HTTPS.
	TLSKey string `yaml:"tls_key"`
}

// AssertionIssuerConfig configures the background assertion generation pipeline.
type AssertionIssuerConfig struct {
	// Enabled turns the assertion issuer on/off (default: true).
	Enabled *bool `yaml:"enabled"`

	// BatchSize is entries per generation batch (default: 100).
	BatchSize int `yaml:"batch_size"`

	// Concurrency is the number of parallel bundle builders (default: 4).
	Concurrency int `yaml:"concurrency"`

	// StalenessThreshold regenerates if proof is >N checkpoints old (default: 5).
	StalenessThreshold int `yaml:"staleness_threshold"`

	// Webhooks is a list of webhook targets to notify after assertion generation.
	Webhooks []WebhookConfig `yaml:"webhooks"`
}

// IsEnabled returns whether the assertion issuer is enabled.
// Defaults to true if not explicitly set.
func (c AssertionIssuerConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// WebhookConfig configures a single webhook notification target.
type WebhookConfig struct {
	// URL is the webhook endpoint to POST to.
	URL string `yaml:"url"`

	// Pattern is a CN/SAN glob pattern to filter which assertions trigger this webhook.
	Pattern string `yaml:"pattern"`

	// Secret is an HMAC-SHA256 secret for the X-MTC-Signature header.
	Secret string `yaml:"secret"`
}

// LocalCAConfig configures the optional local intermediate CA for two-phase
// MTC certificate signing with embedded inclusion proofs.
type LocalCAConfig struct {
	// Enabled turns local CA mode on/off (default: false).
	Enabled bool `yaml:"enabled"`

	// MTCMode enables MTC-spec-compliant certificates (default: false).
	// When true, certificates use signatureAlgorithm = id-alg-mtcProof
	// with the MTCProof in signatureValue instead of a cryptographic signature.
	MTCMode bool `yaml:"mtc_mode"`

	// KeyFile is the path to the ECDSA P-256 private key (PEM).
	KeyFile string `yaml:"key_file"`

	// CertFile is the path to the CA certificate (PEM).
	CertFile string `yaml:"cert_file"`

	// Validity is the default certificate validity period (default: 90 days).
	Validity time.Duration `yaml:"validity"`

	// Organization is the CA subject organization name.
	Organization string `yaml:"organization"`

	// Country is the CA subject country.
	Country string `yaml:"country"`
}

// LogConfig configures the issuance log identity.
type LogConfig struct {
	// Name is a human-readable log name (appears in checkpoints).
	Name string `yaml:"name"`

	// Origin is the checkpoint origin line (e.g., "example.com/mtc-log").
	Origin string `yaml:"origin"`

	// BatchSize is the maximum number of entries to append per cycle.
	BatchSize int `yaml:"batch_size"`
}

// PostgresConfig configures the PostgreSQL state store connection.
type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"ssl_mode"`

	// MaxOpenConns sets the maximum number of open connections.
	MaxOpenConns int `yaml:"max_open_conns"`

	// MaxIdleConns sets the maximum number of idle connections.
	MaxIdleConns int `yaml:"max_idle_conns"`

	// ConnMaxLifetime sets the maximum connection lifetime.
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// DSN returns the PostgreSQL connection string.
func (c PostgresConfig) DSN() string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.Host, c.Port, c.Database, c.Username, c.Password, sslMode,
	)
}

// MariaDBConfig configures the DigiCert CA MariaDB connection.
type MariaDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// IssuerID filters certificates to a specific CA issuer. Empty means all.
	IssuerID string `yaml:"issuer_id"`
}

// DSN returns the MariaDB connection string for go-sql-driver/mysql.
func (c MariaDBConfig) DSN() string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC",
		c.Username, c.Password, c.Host, c.Port, c.Database,
	)
}

// HTTPConfig configures the HTTP server.
type HTTPConfig struct {
	// Addr is the listen address (e.g., ":8080").
	Addr string `yaml:"addr"`

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration `yaml:"read_timeout"`

	// WriteTimeout is the maximum duration before timing out writes.
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// TileCacheTTL is the Cache-Control max-age for full (immutable) tiles.
	TileCacheTTL time.Duration `yaml:"tile_cache_ttl"`

	// CheckpointCacheTTL is the Cache-Control max-age for the checkpoint.
	CheckpointCacheTTL time.Duration `yaml:"checkpoint_cache_ttl"`
}

// WatcherConfig configures the background CA polling loop.
type WatcherConfig struct {
	// PollInterval is how often to poll the CA database for new certificates.
	PollInterval time.Duration `yaml:"poll_interval"`

	// RevocationPollInterval is how often to check for revocations.
	RevocationPollInterval time.Duration `yaml:"revocation_poll_interval"`

	// CheckpointInterval is how often to create a signed checkpoint.
	CheckpointInterval time.Duration `yaml:"checkpoint_interval"`

	// BatchSize is the maximum number of certificates to fetch per poll.
	BatchSize int `yaml:"batch_size"`
}

// CosignerConfig configures the primary signing key.
type CosignerConfig struct {
	// KeyFile is the path to the private key (PEM-encoded).
	KeyFile string `yaml:"key_file"`

	// KeyID is a short identifier for the key (appears in checkpoints).
	KeyID string `yaml:"key_id"`

	// Algorithm is the signature algorithm: "ed25519", "mldsa44", "mldsa65", "mldsa87".
	// Default: "ed25519".
	Algorithm string `yaml:"algorithm"`

	// CosignerID is the numeric identifier for MTCSignature (default: 0).
	CosignerID uint16 `yaml:"cosigner_id"`
}

// AdditionalCosignerConfig configures an additional cosigner (e.g., post-quantum).
type AdditionalCosignerConfig struct {
	// KeyFile is the path to the private key (PEM-encoded).
	KeyFile string `yaml:"key_file"`

	// KeyID is a short identifier for the key.
	KeyID string `yaml:"key_id"`

	// Algorithm is the signature algorithm: "ed25519", "mldsa44", "mldsa65", "mldsa87".
	Algorithm string `yaml:"algorithm"`

	// CosignerID is the TrustAnchorID for MTCSignature (ASCII string, e.g. "32473.1").
	CosignerID string `yaml:"cosigner_id"`
}

// LoggingConfig configures structured logging.
type LoggingConfig struct {
	// Level is the minimum log level: debug, info, warn, error.
	Level string `yaml:"level"`

	// Format is the log format: json or text.
	Format string `yaml:"format"`
}

// Load reads and parses a YAML config file, substituting environment variables.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config.Load: read %s: %w", path, err)
	}

	// Substitute ${VAR} and ${VAR:-default} patterns.
	expanded := expandEnvVars(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("config.Load: parse %s: %w", path, err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

// envVarPattern matches ${VAR} and ${VAR:-default}.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// expandEnvVars replaces ${VAR} and ${VAR:-default} with environment values.
func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := envVarPattern.FindStringSubmatch(match)
		if parts == nil {
			return match
		}
		varName := parts[1]
		defaultVal := parts[2]
		if val, ok := os.LookupEnv(varName); ok {
			return val
		}
		return defaultVal
	})
}

// applyDefaults sets sensible defaults for unset fields.
func applyDefaults(cfg *Config) {
	if cfg.Log.Name == "" {
		cfg.Log.Name = "mtc-bridge"
	}
	if cfg.Log.Origin == "" {
		cfg.Log.Origin = "localhost/mtc-bridge"
	}
	if cfg.Log.BatchSize <= 0 {
		cfg.Log.BatchSize = 100
	}

	if cfg.StateDB.Port == 0 {
		cfg.StateDB.Port = 5432
	}
	if cfg.StateDB.Database == "" {
		cfg.StateDB.Database = "mtcbridge"
	}
	if cfg.StateDB.SSLMode == "" {
		cfg.StateDB.SSLMode = "disable"
	}
	if cfg.StateDB.MaxOpenConns <= 0 {
		cfg.StateDB.MaxOpenConns = 25
	}
	if cfg.StateDB.MaxIdleConns <= 0 {
		cfg.StateDB.MaxIdleConns = 5
	}
	if cfg.StateDB.ConnMaxLifetime <= 0 {
		cfg.StateDB.ConnMaxLifetime = 5 * time.Minute
	}

	if cfg.CADB.Port == 0 {
		cfg.CADB.Port = 3306
	}
	if cfg.CADB.Database == "" {
		cfg.CADB.Database = "digicert_ca"
	}

	if cfg.HTTP.Addr == "" {
		cfg.HTTP.Addr = ":8080"
	}
	if cfg.HTTP.ReadTimeout <= 0 {
		cfg.HTTP.ReadTimeout = 10 * time.Second
	}
	if cfg.HTTP.WriteTimeout <= 0 {
		cfg.HTTP.WriteTimeout = 30 * time.Second
	}
	if cfg.HTTP.TileCacheTTL <= 0 {
		cfg.HTTP.TileCacheTTL = 24 * time.Hour
	}
	if cfg.HTTP.CheckpointCacheTTL <= 0 {
		cfg.HTTP.CheckpointCacheTTL = 5 * time.Second
	}

	if cfg.Watcher.PollInterval <= 0 {
		cfg.Watcher.PollInterval = 10 * time.Second
	}
	if cfg.Watcher.RevocationPollInterval <= 0 {
		cfg.Watcher.RevocationPollInterval = 30 * time.Second
	}
	if cfg.Watcher.CheckpointInterval <= 0 {
		cfg.Watcher.CheckpointInterval = 60 * time.Second
	}
	if cfg.Watcher.BatchSize <= 0 {
		cfg.Watcher.BatchSize = 100
	}

	if cfg.Cosigner.KeyID == "" {
		cfg.Cosigner.KeyID = "mtc-bridge-cosigner"
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	// Assertion issuer defaults.
	if cfg.AssertionIssuer.BatchSize <= 0 {
		cfg.AssertionIssuer.BatchSize = 100
	}
	if cfg.AssertionIssuer.Concurrency <= 0 {
		cfg.AssertionIssuer.Concurrency = 4
	}
	if cfg.AssertionIssuer.StalenessThreshold <= 0 {
		cfg.AssertionIssuer.StalenessThreshold = 5
	}

	// ACME defaults.
	if cfg.ACME.Addr == "" {
		cfg.ACME.Addr = ":8443"
	}
	if cfg.ACME.ExternalURL == "" {
		cfg.ACME.ExternalURL = "http://localhost:8443"
	}
	if cfg.ACME.MTCBridgeURL == "" {
		cfg.ACME.MTCBridgeURL = "http://localhost:8080"
	}
	if cfg.ACME.OrderExpiry <= 0 {
		cfg.ACME.OrderExpiry = 24 * time.Hour
	}
	if cfg.ACME.AssertionTimeout <= 0 {
		cfg.ACME.AssertionTimeout = 5 * time.Minute
	}
	if cfg.ACME.AssertionPollInterval <= 0 {
		cfg.ACME.AssertionPollInterval = 5 * time.Second
	}
}

// ParseLogLevel parses a log level string into an slog.Level.
func ParseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Validate checks the config for required fields and returns an error if invalid.
func (c *Config) Validate() error {
	var errs []string

	if c.StateDB.Host == "" {
		errs = append(errs, "state_db.host is required")
	}
	if c.StateDB.Username == "" {
		errs = append(errs, "state_db.username is required")
	}
	if c.CADB.Host == "" {
		errs = append(errs, "ca_db.host is required")
	}
	if c.CADB.Username == "" {
		errs = append(errs, "ca_db.username is required")
	}
	if c.Cosigner.KeyFile == "" {
		errs = append(errs, "cosigner.key_file is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config.Validate: %s", strings.Join(errs, "; "))
	}
	return nil
}

// String returns a redacted summary for logging.
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{log=%q, state_db=%s:%d/%s, ca_db=%s:%d/%s, http=%s, watcher=%s}",
		c.Log.Name,
		c.StateDB.Host, c.StateDB.Port, c.StateDB.Database,
		c.CADB.Host, c.CADB.Port, c.CADB.Database,
		c.HTTP.Addr,
		c.Watcher.PollInterval,
	)
}

// MustAtoi converts a string to int, panicking on failure. For use in defaults only.
func MustAtoi(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("config.MustAtoi(%q): %v", s, err))
	}
	return v
}
