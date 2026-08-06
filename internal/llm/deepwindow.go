package llm

import (
	"strings"

	"github.com/juanfont/atalaia/internal/detector"
)

// deepWindowHeader prefixes each block with its file so the model can
// name what it is reading. Line numbers are deliberately absent: the
// model never supplies a location, grounding derives it from the diff.
const deepWindowHeader = "=== "

// minDeepWindowTokens floors the per-window budget. A budget smaller
// than this packs one line per call and burns the window cap on
// nothing.
const minDeepWindowTokens = 256

// buildDeepWindows renders the diff's added lines into budget-sized
// windows for the deep read.
//
// Only added lines are scanned. Context and removed lines are dropped:
// a secret that appears only in a removed line was committed in an
// earlier push and belongs to a history scan, not this one. Dropping
// them is also what makes the deep read affordable, since the
// added-line set is a fraction of a typical diff.
//
// Windows are capped at maxWindows (0 means uncapped). When blocks
// remain past the cap, truncated is true and the caller reports
// incomplete coverage rather than a clean scan.
func buildDeepWindows(diff []byte, inputBudget, outputBudget, maxWindows int) ([]string, bool) {
	budget := inputBudget - outputBudget
	if budget < minDeepWindowTokens {
		budget = minDeepWindowTokens
	}

	var (
		windows []string
		cur     strings.Builder
		curTok  int
	)
	flush := func() {
		if cur.Len() > 0 {
			windows = append(windows, cur.String())
			cur.Reset()
			curTok = 0
		}
	}

	for _, block := range detector.WalkDiff(diff) {
		for _, chunk := range splitBlock(block, budget) {
			t := estimateTokens(chunk)
			if curTok > 0 && curTok+t > budget {
				flush()
			}
			cur.WriteString(chunk)
			curTok += t
		}
	}
	flush()

	if maxWindows > 0 && len(windows) > maxWindows {
		return windows[:maxWindows], true
	}
	return windows, false
}

// splitBlock renders one AddedBlock as header plus body, splitting it
// by lines when the block alone exceeds one window's budget. Every
// piece repeats the header so no window is anonymous.
func splitBlock(block detector.AddedBlock, budget int) []string {
	header := deepWindowHeader + block.Path + "\n"
	whole := header + block.Content + "\n"
	if estimateTokens(whole) <= budget {
		return []string{whole}
	}

	var (
		out  []string
		cur  strings.Builder
		head = estimateTokens(header)
	)
	cur.WriteString(header)
	tok := head

	for _, line := range strings.Split(block.Content, "\n") {
		lt := estimateTokens(line) + 1
		if tok > head && tok+lt > budget {
			out = append(out, cur.String())
			cur.Reset()
			cur.WriteString(header)
			tok = head
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		tok += lt
	}
	if tok > head {
		out = append(out, cur.String())
	}
	return out
}
