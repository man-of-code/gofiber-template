package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"gofiber_template/internal/envutil"
)

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("genenv", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	validate := fs.Bool("validate", false, "validate an existing .env file")
	envPath := fs.String("env", ".env", "path to .env file for validation")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *validate {
		return validateEnv(w, *envPath)
	}

	return printGeneratedSecrets(w)
}

func printGeneratedSecrets(w io.Writer) error {
	encKey, err := randomHex(32)
	if err != nil {
		return err
	}
	jwtSecret, err := randomHex(64)
	if err != nil {
		return err
	}
	adminKey, err := randomHex(16)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	fmt.Fprintln(&buf, "Generated secrets (copy into your .env):")
	fmt.Fprintf(&buf, "ENCRYPTION_KEY=%s\n", encKey)
	fmt.Fprintf(&buf, "JWT_SECRET=%s\n", jwtSecret)
	fmt.Fprintf(&buf, "ADMIN_MASTER_KEY=%s\n", adminKey)

	_, err = io.Copy(w, &buf)
	return err
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validateEnv(w io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	values := envutil.Parse(string(data))
	var issues []string

	enc := values["ENCRYPTION_KEY"]
	if len(enc) != 64 {
		issues = append(issues, "ENCRYPTION_KEY should be 64 hex characters for 32 bytes")
	}

	jwt := values["JWT_SECRET"]
	if len(jwt) < 128 {
		issues = append(issues, "JWT_SECRET should have at least 128 hex characters (64 bytes) of entropy")
	}

	admin := values["ADMIN_MASTER_KEY"]
	if len(admin) == 0 {
		issues = append(issues, "ADMIN_MASTER_KEY must be non-empty")
	}

	if len(issues) == 0 {
		fmt.Fprintln(w, "OK: .env secrets look structurally valid.")
		return nil
	}

	fmt.Fprintln(w, "Issues found in .env:")
	for _, iss := range issues {
		fmt.Fprintln(w, "- ", iss)
	}
	return fmt.Errorf("invalid env secrets")
}
