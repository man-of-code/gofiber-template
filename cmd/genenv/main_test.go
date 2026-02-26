package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test that the default (no args) mode prints labeled secrets that look structurally valid.
func TestGenerateModePrintsLabeledSecrets(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf, []string{}); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}

	out := buf.String()
	for _, label := range []string{"ENCRYPTION_KEY", "JWT_SECRET", "ADMIN_MASTER_KEY"} {
		if !strings.Contains(out, label) {
			t.Fatalf("expected output to contain label %q, got:\n%s", label, out)
		}
	}
}

// Test validate mode against a minimal valid env file.
func TestValidateModeWithValidEnv(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	content := strings.Join([]string{
		"ENCRYPTION_KEY=" + strings.Repeat("a", 64),
		"JWT_SECRET=" + strings.Repeat("b", 128),
		"ADMIN_MASTER_KEY=admin-key",
	}, "\n") + "\n"

	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}

	var buf bytes.Buffer
	if err := run(&buf, []string{"-validate", "-env", envPath}); err != nil {
		t.Fatalf("run() returned error in validate mode: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected validate output to contain 'OK', got:\n%s", out)
	}
}

// Test validate mode reports issues for missing/weak values.
func TestValidateModeReportsIssues(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	// Missing ENCRYPTION_KEY and short JWT_SECRET
	content := "JWT_SECRET=short\nADMIN_MASTER_KEY=\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write env file: %v", err)
	}

	var buf bytes.Buffer
	if err := run(&buf, []string{"-validate", "-env", envPath}); err == nil {
		t.Fatalf("expected run() to return error for invalid env, got nil")
	}

	out := buf.String()
	expectSubstrings := []string{
		"ENCRYPTION_KEY",
		"JWT_SECRET",
		"ADMIN_MASTER_KEY",
	}
	for _, sub := range expectSubstrings {
		if !strings.Contains(out, sub) {
			t.Fatalf("expected validate output to mention %q, got:\n%s", sub, out)
		}
	}
}
