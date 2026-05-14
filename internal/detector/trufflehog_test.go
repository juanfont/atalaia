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
	th := NewTrufflehog(types.TrufflehogConfig{Binary: "trufflehog"})
	findings, err := th.Scan(context.Background(), loadDiff(t, "aws_sentinel.diff"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one trufflehog finding on AWS sentinel diff")
	}
}
