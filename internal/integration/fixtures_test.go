package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
)

// This runs in ordinary go test ./... without an LLM or subprocess
// detector. Labels must be deliberate and every expected location must
// point to actual added bytes, not a removed or context-only secret.
func TestCorpusFixtures(t *testing.T) {
	entries, err := filepath.Glob("testdata/*/*.diff")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("empty corpus")
	}
	pairs := map[string]map[string]int{}
	for _, path := range entries {
		name := strings.TrimSuffix(filepath.Base(path), ".diff")
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(strings.TrimSuffix(path, ".diff") + ".expect.json")
			if err != nil {
				t.Fatal(err)
			}
			var fx fixture
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&fx); err != nil {
				t.Fatal(err)
			}
			if fx.Description == "" {
				t.Error("missing description")
			}
			if !hasTag(fx, "expanded") {
				return
			}
			if err := validateHunks(string(body)); err != nil {
				t.Fatal(err)
			}
			if !fx.Deep {
				t.Error("expanded fixtures must exercise both channels")
			}
			if fx.MaxAlerts == nil || fx.MaxUnreviewed == nil || *fx.MaxUnreviewed != 0 {
				t.Fatal("expanded fixtures require alert and zero-unreviewed limits")
			}
			if fx.Pair == "" {
				t.Error("missing contrast pair")
			}
			positive, negative := hasTag(fx, "positive"), hasTag(fx, "negative")
			if positive == negative {
				t.Fatal("require exactly one polarity tag")
			}
			polarity := "negative"
			if positive {
				polarity = "positive"
			}
			if pairs[fx.Pair] == nil {
				pairs[fx.Pair] = map[string]int{}
			}
			pairs[fx.Pair][polarity]++
			if positive && (len(fx.ExpectSecrets) == 0 || *fx.MaxAlerts < len(fx.ExpectSecrets)) {
				t.Error("positive case must require secrets and allow those alerts")
			}
			if negative && (len(fx.ExpectSecrets) > 0 || *fx.MaxAlerts != 0) {
				t.Error("negative case must require zero alerts")
			}
			if !strings.HasSuffix(name, "_"+polarity) {
				t.Error("filename and polarity disagree")
			}
			added := map[string]map[int]string{}
			for _, block := range detector.WalkDiff(body) {
				if added[block.Path] == nil {
					added[block.Path] = map[int]string{}
				}
				for i, line := range strings.Split(block.Content, "\n") {
					added[block.Path][block.StartLine+i] = line
				}
			}
			seen := map[string]bool{}
			for _, want := range fx.ExpectSecrets {
				if want.Kind != "credential" && want.Kind != "private_key" {
					t.Errorf("invalid public kind %q", want.Kind)
				}
				if want.Value == "" || want.File == "" || want.Line < 1 {
					t.Error("expected secret requires file, positive line, and source value")
				}
				line, ok := added[want.File][want.Line]
				if !ok || !strings.Contains(line, want.Value) {
					t.Errorf("expected source value absent at added location %s:%d", want.File, want.Line)
				}
				key := fmt.Sprintf("%s:%d", want.File, want.Line)
				if seen[key] {
					t.Errorf("duplicate location %s could reuse one alert for two expectations", key)
				}
				seen[key] = true
			}
		})
	}
	for name, polarities := range pairs {
		if polarities["positive"] != 1 || polarities["negative"] != 1 {
			t.Errorf("pair %s must contain exactly one positive and one negative: %v", name, polarities)
		}
	}
	expectations, err := filepath.Glob("testdata/*/*.expect.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range expectations {
		if _, err := os.Stat(strings.TrimSuffix(path, ".expect.json") + ".diff"); err != nil {
			t.Errorf("orphan expectation %s", path)
		}
	}
}

var hunkRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

func validateHunks(diff string) error {
	active := false
	oldWant, newWant, oldGot, newGot := 0, 0, 0, 0
	check := func() error {
		if active && (oldWant != oldGot || newWant != newGot) {
			return fmt.Errorf("hunk counts: got -%d +%d, header says -%d +%d", oldGot, newGot, oldWant, newWant)
		}
		return nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(diff, "\n"), "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			if err := check(); err != nil {
				return err
			}
			active = false
			continue
		}
		if strings.HasPrefix(line, "@@") {
			if err := check(); err != nil {
				return err
			}
			m := hunkRE.FindStringSubmatch(line)
			if m == nil {
				return fmt.Errorf("invalid hunk %q", line)
			}
			oldWant, newWant = 1, 1
			if m[2] != "" {
				oldWant, _ = strconv.Atoi(m[2])
			}
			if m[4] != "" {
				newWant, _ = strconv.Atoi(m[4])
			}
			oldGot, newGot = 0, 0
			active = true
			continue
		}
		if !active {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			newGot++
		case strings.HasPrefix(line, "-"):
			oldGot++
		case strings.HasPrefix(line, " "):
			oldGot++
			newGot++
		case strings.HasPrefix(line, "\\ No newline at end of file"):
		default:
			return fmt.Errorf("invalid hunk body line %q", line)
		}
	}
	return check()
}

func TestValidateHunks(t *testing.T) {
	for _, tc := range []struct {
		name, diff string
		valid      bool
	}{
		{"addition", "@@ -0,0 +1,1 @@\n+hello\n", true},
		{"removal", "@@ -1,1 +0,0 @@\n-hello\n", true},
		{"context", "@@ -1,2 +1,2 @@\n same\n-before\n+after\n", true},
		{"wrong-count", "@@ -0,0 +1,2 @@\n+hello\n", false},
		{"unmarked-content", "@@ -0,0 +1,1 @@\nhello\n", false},
		{"rename-only", "diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHunks(tc.diff); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestFoundSecret(t *testing.T) {
	want := secretExpectation{File: "app.py", Line: 7, Kind: "credential", Value: "not-read-from-response"}
	for _, tc := range []struct {
		name  string
		resp  checkResponse
		found bool
	}{
		{"confirmed", checkResponse{Verdicts: []verdict{{File: "app.py", Line: 7, Verdict: "confirmed", Confidence: 0.9}}}, true},
		{"discovered", checkResponse{Discoveries: []discovery{{File: "app.py", Line: 7, Kind: "credential"}}}, true},
		{"dismissed", checkResponse{Verdicts: []verdict{{File: "app.py", Line: 7, Verdict: "dismissed"}}}, false},
		{"unreviewed", checkResponse{Verdicts: []verdict{{File: "app.py", Line: 7, Verdict: "unreviewed"}}}, false},
		{"legacy-gap", checkResponse{Verdicts: []verdict{{File: "app.py", Line: 7, Verdict: "confirmed", Reason: "model returned no verdict for this finding"}}}, false},
		{"wrong-line", checkResponse{Discoveries: []discovery{{File: "app.py", Line: 8, Kind: "credential"}}}, false},
		{"wrong-file", checkResponse{Discoveries: []discovery{{File: "other.py", Line: 7, Kind: "credential"}}}, false},
		{"wrong-kind", checkResponse{Discoveries: []discovery{{File: "app.py", Line: 7, Kind: "test_data"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := foundSecret(&tc.resp, want); got != tc.found {
				t.Fatalf("found=%v want=%v", got, tc.found)
			}
		})
	}
}

func TestAlertCount(t *testing.T) {
	response := checkResponse{Verdicts: []verdict{{Verdict: "confirmed"}, {Verdict: "dismissed"}, {Verdict: "unreviewed"}}, Discoveries: []discovery{{Kind: "credential"}}}
	if got := alertCount(&response); got != 2 {
		t.Fatalf("got %d alerts, want confirmed plus discovery only", got)
	}
}

func TestCompleteCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		complete   bool
	}{
		{"complete", `{"stats":{"deep_scan":{"ran":true,"status":"complete"}}}`, true},
		{"partial", `{"stats":{"deep_scan":{"ran":true,"status":"partial"}}}`, false},
		{"not-run", `{"stats":{"deep_scan":{"ran":false,"status":"complete"}}}`, false},
		{"deep-truncated", `{"stats":{"deep_scan":{"ran":true,"status":"complete","truncated":true}}}`, false},
		{"deep-error", `{"stats":{"deep_scan":{"ran":true,"status":"complete","error":"timeout"}}}`, false},
		{"detector-error", `{"stats":{"detector_errors":[{"detector":"gitleaks"}],"deep_scan":{"ran":true,"status":"complete"}}}`, false},
		{"findings-truncated", `{"stats":{"truncated":true,"deep_scan":{"ran":true,"status":"complete"}}}`, false},
		{"missing-deep", `{"stats":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp checkResponse
			if err := json.Unmarshal([]byte(tc.body), &resp); err != nil {
				t.Fatal(err)
			}
			if got := completeCoverage(&resp); got != tc.complete {
				t.Fatalf("complete=%v want=%v", got, tc.complete)
			}
		})
	}
}

func TestFrozenHoldout(t *testing.T) {
	for _, set := range []struct {
		name  string
		pairs int
	}{{"holdout", 40}, {"holdout3", 24}, {"holdout4", 16}} {
		t.Run(set.name, func(t *testing.T) {
			dir := filepath.Join("testdata", set.name)
			raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Pairs, Fixtures int
				SHA256          map[string]string
			}
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.Pairs != set.pairs || manifest.Fixtures != set.pairs*2 || len(manifest.SHA256) != set.pairs*4 {
				t.Fatalf("holdout must contain %d frozen contrast pairs", set.pairs)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".diff") || strings.HasSuffix(entry.Name(), ".expect.json") {
					if _, ok := manifest.SHA256[entry.Name()]; !ok {
						t.Errorf("unfrozen fixture: %s", entry.Name())
					}
				}
			}
			for name, expected := range manifest.SHA256 {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				if hex.EncodeToString(sum[:]) != expected {
					t.Errorf("frozen holdout changed: %s", name)
				}
			}
		})
	}
}
