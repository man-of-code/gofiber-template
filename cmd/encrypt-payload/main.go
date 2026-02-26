// encrypt-payload encrypts a JSON payload using ENCRYPTION_KEY from .env.
//
// Usage:
//
//	go run ./cmd/encrypt-payload [payload]
//	echo '{"name":"test"}' | go run ./cmd/encrypt-payload
//
// With argument: encrypts the given string.
// Without argument: reads from stdin.
//
// Output: hex-encoded ciphertext (same format as X-Encrypted-Payload: true requests).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"gofiber_template/internal/services"
)

func main() {
	loadEnv()
	cryptoService, err := services.NewCryptoService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	var payload []byte
	if len(os.Args) > 1 {
		payload = []byte(strings.Join(os.Args[1:], " "))
	} else {
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}
	ct, err := cryptoService.EncryptPayload(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encrypting: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(ct))
}

// loadEnv reads .env from cwd or parent and sets env vars (only if not already set).
func loadEnv() {
	for _, p := range []string{".env", "../.env"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			idx := strings.Index(line, "=")
			if idx == -1 {
				continue
			}
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"'")
			if key != "" && os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
		f.Close()
		return
	}
}
