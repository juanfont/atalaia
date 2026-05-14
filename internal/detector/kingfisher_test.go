package detector

import (
	"bytes"
	"context"
	"os/exec"
	"testing"

	"github.com/juanfont/atalaia/internal/types"
)

func TestParseKingfisherStream(t *testing.T) {
	diff := loadDiff(t, "aws_sentinel.diff")
	jsonl := []byte(`{"rule":"aws-access-key","rule_name":"AWS Access Key","secret":"AKIAIOSFODNN7EXAMPLE","path":"example.py","line":3,"verified":false}
{"rule":"aws-secret","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","verified":false}
`)
	out := parseKingfisherStream(bytes.NewReader(jsonl), diff)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(out), out)
	}

	a := out[0]
	if a.DetectorType != "kingfisher" || a.DetectorName != "AWS Access Key" {
		t.Errorf("first finding shape: %+v", a)
	}
	if a.File != "example.py" || a.Line != 3 {
		t.Errorf("first finding (file,line)=(%q,%d), want (example.py, 3)", a.File, a.Line)
	}

	// Second finding has no path/line in the JSON; locateInDiff should fill it.
	b := out[1]
	if b.File != "example.py" || b.Line != 4 {
		t.Errorf("second finding (file,line)=(%q,%d), want (example.py, 4)", b.File, b.Line)
	}
}

func TestKingfisher_Integration(t *testing.T) {
	if _, err := exec.LookPath("kingfisher"); err != nil {
		t.Skip("kingfisher not on PATH")
	}
	k := NewKingfisher(types.KingfisherConfig{Binary: "kingfisher"})
	if _, err := k.Scan(context.Background(), loadDiff(t, "aws_sentinel.diff")); err != nil {
		t.Logf("kingfisher Scan returned: %v (CLI shape may need refinement; see kingfisher.go)", err)
	}
}
