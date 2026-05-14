package detector

import (
	"bytes"
	"context"
	"os/exec"
	"testing"

	"github.com/juanfont/atalaia/internal/types"
)

func TestParseTrufflehogStream(t *testing.T) {
	diff := loadDiff(t, "multi_file.diff")
	jsonl := []byte(`{"DetectorName":"aws","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Stdin":{}}}}
some non-json garbage line
{"DetectorName":"postgres","Verified":false,"Raw":"postgresql://admin:s3cret@db.example.com:5432/prod"}
`)
	out := parseTrufflehogStream(bytes.NewReader(jsonl), diff)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(out), out)
	}

	aws := out[0]
	if aws.DetectorType != "trufflehog" || aws.DetectorName != "aws" || !aws.Verified {
		t.Errorf("aws finding wrong shape: %+v", aws)
	}
	if aws.File != "src/db.py" || aws.Line != 14 {
		t.Errorf("aws finding (file,line)=(%q,%d), want (src/db.py, 14)", aws.File, aws.Line)
	}

	pg := out[1]
	if pg.DetectorName != "postgres" {
		t.Errorf("pg DetectorName=%q, want postgres", pg.DetectorName)
	}
	if pg.File != "src/db.py" || pg.Line != 12 {
		t.Errorf("pg finding (file,line)=(%q,%d), want (src/db.py, 12)", pg.File, pg.Line)
	}
	if pg.Verified {
		t.Errorf("pg.Verified=true, want false")
	}
}

func TestTrufflehog_Integration(t *testing.T) {
	if _, err := exec.LookPath("trufflehog"); err != nil {
		t.Skip("trufflehog not on PATH")
	}
	// Use the non-sentinel fixture: trufflehog (like gitleaks)
	// allowlists AKIAIOSFODNN7EXAMPLE as a documented AWS sample, so
	// scanning aws_sentinel.diff returns zero findings.
	th := NewTrufflehog(types.TrufflehogConfig{Binary: "trufflehog"})
	if _, err := th.Scan(context.Background(), loadDiff(t, "real_key.diff")); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// We don't assert a non-empty finding list: depending on the
	// trufflehog version, generic AWS-format keys may or may not be
	// emitted without verification. The check that matters is the
	// subprocess runs cleanly and produces parseable JSONL.
}
