package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrtimp/headless-cognito/internal/auth"
)

func TestReadResultRejectsMissingFile(t *testing.T) {
	_, err := readResult(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("readResult error = %v, want missing-file error", err)
	}
}

func TestReadResultRejectsMissingCookie(t *testing.T) {
	file := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(file, []byte(`{"cookies":{"AWSALBAuthNonce":"nonce"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readResult(file)
	if err == nil || !strings.Contains(err.Error(), "AWSELBAuthSessionCookie-0") {
		t.Fatalf("readResult error = %v, want missing-cookie error", err)
	}
}

func TestReadResultAcceptsCompleteResult(t *testing.T) {
	file := filepath.Join(t.TempDir(), "auth.json")
	contents := `{"cookies":{"AWSALBAuthNonce":"nonce","AWSELBAuthSessionCookie-0":"session-0","AWSELBAuthSessionCookie-1":"session-1"}}`
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := readResult(file)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cookies["AWSALBAuthNonce"] != "nonce" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestValidateResultRejectsEmptyCookie(t *testing.T) {
	result := auth.Result{Cookies: map[string]string{
		"AWSALBAuthNonce":           "nonce",
		"AWSELBAuthSessionCookie-0": "session-0",
		"AWSELBAuthSessionCookie-1": " ",
	}}
	if err := validateResult(result); err == nil {
		t.Fatal("validateResult unexpectedly accepted an empty cookie")
	}
}
