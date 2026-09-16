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

func TestScrub(t *testing.T) {
	secret := "sOqYBsNTwA79IjosZx9y"
	in := "The matched value '" + secret + "' appears to be a literal API key."
	out := Scrub(in, secret)
	if strings.Contains(out, secret) {
		t.Fatalf("Scrub left the raw secret in: %q", out)
	}
	if !strings.Contains(out, Preview(secret)) {
		t.Errorf("Scrub should leave the redacted preview: %q", out)
	}
	// no occurrence -> unchanged
	if got := Scrub("nothing sensitive here", secret); got != "nothing sensitive here" {
		t.Errorf("Scrub mutated text with no secret: %q", got)
	}
	// blank secret -> unchanged
	if got := Scrub("keep me", ""); got != "keep me" {
		t.Errorf("Scrub mutated text on blank secret: %q", got)
	}
}

func TestScrub_ConnectionStringComponents(t *testing.T) {
	for _, tc := range []struct {
		name, secret, reason string
		private              []string
	}{
		{"password fragment", "postgres://reporter:BirchHarbor62@db.internal/reports", "Literal password BirchHarbor62 in a connection string", []string{"BirchHarbor62"}},
		{"encoded and decoded", "https://reader:Pine%4aHill%3a82@service.internal/", "Password Pine%4aHill%3a82 decodes to PineJHill:82", []string{"Pine%4aHill%3a82", "PineJHill:82"}},
		{"token username", "https://q7Nm9Vx4Kr6Ds2Pa@git.internal/repo", "The token q7Nm9Vx4Kr6Ds2Pa is used as username", []string{"q7Nm9Vx4Kr6Ds2Pa"}},
		{"mysql password", "reader:Forest(27)@tcp(db.internal:3306)/orders", "The password Forest(27) is literal", []string{"Forest(27)"}},
		{"mysql embedded at", "reader:Forest@Hill27@tcp(db.internal:3306)/orders", "Password Forest@Hill27 in DSN", []string{"Forest@Hill27"}},
		{"unix socket", "reader:BirchHarbor62@unix(/tmp/db.sock)/orders", "Password BirchHarbor62 in DSN", []string{"BirchHarbor62"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Scrub(tc.reason, tc.secret)
			for _, value := range tc.private {
				if strings.Contains(got, value) {
					t.Fatal("credential component leaked")
				}
			}
			if !strings.Contains(got, "****") {
				t.Fatal("missing redaction mask")
			}
		})
	}
}

func TestPreview_MySQLDSN(t *testing.T) {
	// Generic head/tail masking would reveal the entire two-character password.
	if got := Preview("u:pw@tcp(db.internal:3306)/orders"); got != "****:****@tcp(db.internal:3306)/orders" {
		t.Fatalf("unexpected DSN preview: %s", got)
	}
}
