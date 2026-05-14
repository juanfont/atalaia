package detector

import "sort"

// Detection is the per-detector trail kept for one DedupedFinding.
// Multiple detectors firing on the same (file, line, match) collapse
// into one DedupedFinding whose Detections list captures who fired
// and in what state.
type Detection struct {
	DetectorType string
	DetectorName string
	Rule         string
	Verified     bool
}

// DedupedFinding is the canonical post-dedup unit consumed by the LLM
// and API layers. AnyVerified is true iff at least one underlying
// detector verified the secret against a provider API — this is the
// signal that short-circuits straight to a "confirmed" verdict.
type DedupedFinding struct {
	ID          string
	File        string
	Line        int
	Match       string
	Detections  []Detection
	AnyVerified bool
}

type dedupKey struct {
	file  string
	line  int
	match string
}

// Dedup collapses findings by (file, line, match). Detection order
// within a DedupedFinding is preserved by insertion; the output slice
// itself is sorted by (file, line) for deterministic responses.
func Dedup(findings []Finding) []DedupedFinding {
	byKey := map[dedupKey]*DedupedFinding{}
	var order []dedupKey
	for _, f := range findings {
		k := dedupKey{file: f.File, line: f.Line, match: f.Match}
		cur, ok := byKey[k]
		if !ok {
			cur = &DedupedFinding{
				ID:    FindingID(f),
				File:  f.File,
				Line:  f.Line,
				Match: f.Match,
			}
			byKey[k] = cur
			order = append(order, k)
		}
		cur.Detections = append(cur.Detections, Detection{
			DetectorType: f.DetectorType,
			DetectorName: f.DetectorName,
			Rule:         f.Rule,
			Verified:     f.Verified,
		})
		if f.Verified {
			cur.AnyVerified = true
		}
	}

	out := make([]DedupedFinding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
