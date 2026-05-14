package redact

import (
	"strings"
	"testing"
)

func TestPreview_URL(t *testing.T) {
	in := "postgresql://admin:s3cret@db.example.com:5432/prod"
	got := Preview(in)
	if strings.Contains(got, "admin") || strings.Contains(got, "s3cret") {
		t.Errorf("Preview leaked credentials: %q", got)
	}
	if !strings.Contains(got, "db.example.com") {
		t.Errorf("Preview should keep host visible: %q", got)
	}
	if !strings.Contains(got, "****") {
		t.Errorf("Preview missing mask: %q", got)
	}
}

func TestPreview_Generic(t *testing.T) {
	in := "AKIAIOSFODNN7EXAMPLE"
	got := Preview(in)
	if got == in {
		t.Errorf("Preview did not mask: %q", got)
	}
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("Preview should keep 4-char head: %q", got)
	}
	if !strings.HasSuffix(got, "MPLE") {
		t.Errorf("Preview should keep 4-char tail: %q", got)
	}
	if !strings.Contains(got, "****") {
		t.Errorf("Preview missing mask: %q", got)
	}
}

func TestPreview_Short(t *testing.T) {
	if got := Preview("abc"); got != "****" {
		t.Errorf("Preview(short) = %q, want ****", got)
	}
}

func TestPreview_Empty(t *testing.T) {
	if got := Preview(""); got != "" {
		t.Errorf("Preview(\"\") = %q, want \"\"", got)
	}
}
