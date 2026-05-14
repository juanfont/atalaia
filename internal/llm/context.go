package llm

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/juanfont/atalaia/internal/detector"
)

// estimateTokens is the cheap chars/4 heuristic. English code averages
// near 4 chars/token; Atalaia uses this for the fast-path budget check
// before any LLM call. A tokenizer pass is a future-work item if drift
// becomes visible (see plan, milestone 5).
func estimateTokens(text string) int {
	return (len(text) + 3) / 4
}

// fileIndex is the post-image of a unified diff, organized by file
// and new-file line number. Each entry is one line from the new file
// (added or unchanged context), so per-finding context extraction is
// a slice operation on the sorted line list for that file.
type fileIndex map[string]*fileLines

type fileLines struct {
	nums []int          // sorted ascending
	text map[int]string // lineNum -> raw line text (no diff prefix)
}

// buildFileIndex walks the diff once and yields the index used by
// findingContext.
func buildFileIndex(diff []byte) fileIndex {
	idx := fileIndex{}
	var path string
	var newLine int

	add := func(p string, n int, t string) {
		if p == "" || n <= 0 {
			return
		}
		fl, ok := idx[p]
		if !ok {
			fl = &fileLines{text: map[int]string{}}
			idx[p] = fl
		}
		if _, dup := fl.text[n]; !dup {
			fl.nums = append(fl.nums, n)
		}
		fl.text[n] = t
	}

	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			path = ""
			newLine = 0
		case strings.HasPrefix(line, "+++ "):
			path = parseNewIndexPath(line[4:])
		case strings.HasPrefix(line, "--- "):
			// old-image path; ignored
		case strings.HasPrefix(line, "@@"):
			newLine = parseHunkNewStartLocal(line)
		case strings.HasPrefix(line, "\\ "):
			// "\ No newline at end of file"
		case strings.HasPrefix(line, "+"):
			add(path, newLine, line[1:])
			newLine++
		case strings.HasPrefix(line, "-"):
			// removed; no advance
		case strings.HasPrefix(line, " "):
			add(path, newLine, line[1:])
			newLine++
		default:
			// blank or no-marker — treat as context inside an active hunk
			if newLine > 0 {
				add(path, newLine, line)
				newLine++
			}
		}
	}

	for _, fl := range idx {
		sort.Ints(fl.nums)
	}
	return idx
}

// findingContext returns the ±n surrounding new-file lines for a
// (file, line), formatted as "<num>: <text>" with the matched line
// highlighted. Returns "" when the file isn't in the diff.
func findingContext(idx fileIndex, file string, line, n int) string {
	fl, ok := idx[file]
	if !ok {
		return ""
	}
	low, high := line-n, line+n
	var b strings.Builder
	width := digitWidth(high)
	for _, ln := range fl.nums {
		if ln < low {
			continue
		}
		if ln > high {
			break
		}
		marker := " "
		if ln == line {
			marker = ">"
		}
		fmt.Fprintf(&b, "%s %*d: %s\n", marker, width, ln, fl.text[ln])
	}
	return strings.TrimRight(b.String(), "\n")
}

func digitWidth(n int) int {
	if n < 1 {
		return 1
	}
	w := 0
	for n > 0 {
		w++
		n /= 10
	}
	return w
}

// fitsSingleCall returns true when the whole diff plus a render of all
// findings comfortably fits the input budget (InputTokens - OutputTokens).
// A small safety margin guards against tokenizer drift. An unset /
// non-positive InputTokens is treated as "no budget configured" and
// resolves to single-call mode.
func fitsSingleCall(diff []byte, findings []detector.DedupedFinding, inputBudget, outputBudget int) bool {
	if inputBudget <= 0 {
		return true
	}
	const renderPerFinding = 200 // rough per-finding header overhead in chars
	overhead := 0
	for _, f := range findings {
		overhead += len(f.Match) + len(f.File) + renderPerFinding
	}
	estimate := estimateTokens(string(diff)) + estimateTokens(strings.Repeat(" ", overhead))
	budget := inputBudget - outputBudget
	if budget <= 0 {
		return false
	}
	// 90% of the budget — leave room for the system prompt and tokenizer slack.
	return estimate <= (budget*9)/10
}

// packBatches groups findings into chunks whose rendered per-finding
// blocks (each carrying its surrounding context) fit within the input
// budget. Each batch is processed in its own LLM call.
func packBatches(findings []detector.DedupedFinding, idx fileIndex, contextLines, inputBudget, outputBudget int) [][]PromptFinding {
	budget := inputBudget - outputBudget
	if budget <= 0 {
		budget = inputBudget
	}
	// reserve some headroom for the system prompt and tokenizer slack
	effective := (budget * 9) / 10

	var batches [][]PromptFinding
	var current []PromptFinding
	currentTokens := 0
	for _, f := range findings {
		ctx := findingContext(idx, f.File, f.Line, contextLines)
		pf := PromptFinding{
			ID:         f.ID,
			File:       f.File,
			Line:       f.Line,
			Match:      f.Match,
			Detections: f.Detections,
			Context:    ctx,
		}
		ft := estimateTokens(promptFindingApproxBody(pf))
		// If this single finding alone exceeds the per-call effective
		// budget, send it in its own batch — better degraded than
		// failed.
		if len(current) > 0 && currentTokens+ft > effective {
			batches = append(batches, current)
			current = nil
			currentTokens = 0
		}
		current = append(current, pf)
		currentTokens += ft
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

// promptFindingApproxBody is the rough text we'll render for one
// finding in per-finding mode. Used only for the token estimate.
func promptFindingApproxBody(pf PromptFinding) string {
	var b strings.Builder
	b.WriteString("finding_id=")
	b.WriteString(pf.ID)
	b.WriteString(" file=")
	b.WriteString(pf.File)
	b.WriteString(" line=")
	b.WriteString(strconv.Itoa(pf.Line))
	b.WriteString("\nmatch: ")
	b.WriteString(pf.Match)
	b.WriteByte('\n')
	b.WriteString(pf.Context)
	b.WriteByte('\n')
	return b.String()
}

// parseNewIndexPath mirrors detector.parseNewPath; duplicated here so
// the llm package owns its diff walker without depending on detector
// internals beyond the DedupedFinding shape.
func parseNewIndexPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(raw, "b/") {
		return raw[2:]
	}
	return raw
}

func parseHunkNewStartLocal(line string) int {
	plus := strings.Index(line, "+")
	if plus < 0 {
		return 0
	}
	rest := line[plus+1:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}
