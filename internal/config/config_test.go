package config

import (
	"log/slog"
	"os"
	"testing"
)

func TestExpandEnvVars(t *testing.T) {
	os.Setenv("TEST_HOST", "myhost")
	os.Setenv("TEST_PORT", "5432")
	defer os.Unsetenv("TEST_HOST")
	defer os.Unsetenv("TEST_PORT")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "${TEST_HOST}", "myhost"},
		{"with_default_set", "${TEST_HOST:-fallback}", "myhost"},
		{"with_default_unset", "${UNSET_VAR:-fallback}", "fallback"},
		{"unset_no_default", "${UNSET_VAR}", ""},
		{"embedded", "host=${TEST_HOST}:${TEST_PORT}", "host=myhost:5432"},
		{"no_vars", "plain text", "plain text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandEnvVars(tt.input)
			if got != tt.want {
				t.Errorf("expandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.Log.Name != "mtc-bridge" {
		t.Errorf("default log name = %q, want %q", cfg.Log.Name, "mtc-bridge")
	}
	if cfg.StateDB.Port != 5432 {
		t.Errorf("default state_db port = %d, want 5432", cfg.StateDB.Port)
	}
	if cfg.CADB.Port != 3306 {
		t.Errorf("default ca_db port = %d, want 3306", cfg.CADB.Port)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("default http addr = %q, want %q", cfg.HTTP.Addr, ":8080")
	}
}

func TestPostgresDSN(t *testing.T) {
	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "mtcbridge",
		Username: "user",
		Password: "pass",
		SSLMode:  "disable",
	}
	want := "host=localhost port=5432 dbname=mtcbridge user=user password=pass sslmode=disable"
	if got := cfg.DSN(); got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestMariaDBDSN(t *testing.T) {
	cfg := MariaDBConfig{
		Host:     "ca-db",
		Port:     3306,
		Database: "digicert_ca",
		Username: "caadmin",
		Password: "capassword",
	}
	want := "caadmin:capassword@tcp(ca-db:3306)/digicert_ca?parseTime=true&loc=UTC"
	if got := cfg.DSN(); got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for empty config")
	}

	cfg.StateDB.Host = "localhost"
	cfg.StateDB.Username = "user"
	cfg.CADB.Host = "ca-db"
	cfg.CADB.Username = "caadmin"
	cfg.Cosigner.KeyFile = "/etc/mtc-bridge/key.pem"

	err = cfg.Validate()
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
	}
	for _, tt := range tests {
		if got := ParseLogLevel(tt.input); got != tt.want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	yaml := `
log:
  name: test-log
  origin: test.example.com/mtc
state_db:
  host: localhost
  port: 5432
  username: mtcuser
  password: mtcpass
ca_db:
  host: ca-db
  port: 3306
  username: caadmin
  password: capassword
cosigner:
  key_file: /tmp/key.pem
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Name != "test-log" {
		t.Errorf("log name = %q, want %q", cfg.Log.Name, "test-log")
	}
	if cfg.CADB.Host != "ca-db" {
		t.Errorf("ca_db host = %q, want %q", cfg.CADB.Host, "ca-db")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}
