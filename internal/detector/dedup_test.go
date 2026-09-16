package detector

import (
	"reflect"
	"testing"
)

func TestFindingID_Stable(t *testing.T) {
	f := Finding{File: "a.py", Line: 7, Match: "AKIAIOSFODNN7EXAMPLE"}
	id1 := FindingID(f)
	id2 := FindingID(f)
	if id1 != id2 {
		t.Errorf("FindingID not stable: %q vs %q", id1, id2)
	}
	if len(id1) != 12 {
		t.Errorf("FindingID len=%d, want 12", len(id1))
	}
}

func TestFindingID_DiffersByField(t *testing.T) {
	base := Finding{File: "a.py", Line: 7, Match: "secret"}
	cases := []Finding{
		{File: "b.py", Line: 7, Match: "secret"},
		{File: "a.py", Line: 8, Match: "secret"},
		{File: "a.py", Line: 7, Match: "other"},
	}
	baseID := FindingID(base)
	for _, c := range cases {
		if FindingID(c) == baseID {
			t.Errorf("expected different ID for %+v", c)
		}
	}
}

func TestDedup_CollapsesByTriple(t *testing.T) {
	in := []Finding{
		{DetectorType: "gitleaks", DetectorName: "aws-access-token", Rule: "aws-access-token", File: "a.py", Line: 3, Match: "AKIAIOSFODNN7EXAMPLE"},
		{DetectorType: "trufflehog", DetectorName: "aws", Rule: "aws", File: "a.py", Line: 3, Match: "AKIAIOSFODNN7EXAMPLE", Verified: true},
		{DetectorType: "gitleaks", DetectorName: "generic", Rule: "generic", File: "b.py", Line: 1, Match: "AKIAIOSFODNN7EXAMPLE"},
	}
	out := Dedup(in)
	if len(out) != 2 {
		t.Fatalf("got %d dedup'd findings, want 2: %+v", len(out), out)
	}
	// Output is sorted by (file, line); a.py comes before b.py.
	if out[0].File != "a.py" || out[0].Line != 3 {
		t.Errorf("out[0] = %+v, want a.py:3", out[0])
	}
	if len(out[0].Detections) != 2 {
		t.Errorf("out[0].Detections=%d, want 2", len(out[0].Detections))
	}
	if !out[0].AnyVerified {
		t.Errorf("out[0].AnyVerified=false, want true (trufflehog verified)")
	}
	if out[1].File != "b.py" || out[1].AnyVerified {
		t.Errorf("out[1] = %+v, want b.py with AnyVerified=false", out[1])
	}
}

func TestDedup_EmptyInput(t *testing.T) {
	if got := Dedup(nil); len(got) != 0 {
		t.Errorf("Dedup(nil) = %v, want empty", got)
	}
}

func TestDedup_IndependentOfScannerCompletionOrder(t *testing.T) {
	findings := []Finding{
		{DetectorType: "gitleaks", DetectorName: "local", Rule: "z-rule", File: "a", Line: 1, Match: "first"},
		{DetectorType: "gitleaks", DetectorName: "local", Rule: "a-rule", File: "a", Line: 1, Match: "first"},
		{DetectorType: "gitleaks", DetectorName: "local", Rule: "a-rule", File: "a", Line: 1, Match: "first", Verified: true},
		{DetectorType: "trufflehog", DetectorName: "remote", Rule: "key", File: "a", Line: 1, Match: "first"},
		{DetectorType: "gitleaks", DetectorName: "local", Rule: "generic", File: "a", Line: 1, Match: "second"},
		{DetectorType: "gitleaks", DetectorName: "local", Rule: "generic", File: "b", Line: 2, Match: "third"},
	}
	expected := Dedup(findings)
	if len(expected) != 3 || len(expected[0].Detections) != 4 || !expected[0].AnyVerified || expected[1].AnyVerified {
		t.Fatalf("lost provenance or verification: %+v", expected)
	}
	var visit func(int)
	visit = func(start int) {
		if start == len(findings) {
			before := append([]Finding(nil), findings...)
			if got := Dedup(findings); !reflect.DeepEqual(got, expected) {
				t.Fatalf("scanner order changed canonical findings: %+v", got)
			}
			if !reflect.DeepEqual(before, findings) {
				t.Fatal("mutated scanner results")
			}
			return
		}
		for i := start; i < len(findings); i++ {
			findings[start], findings[i] = findings[i], findings[start]
			visit(start + 1)
			findings[start], findings[i] = findings[i], findings[start]
		}
	}
	visit(0) // all 720 possible scanner completion orders
}
