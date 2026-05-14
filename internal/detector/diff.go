package detector

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// AddedBlock is a contiguous run of '+' lines from a single hunk, with
// the post-image line number of the first added line. Detectors that
// operate on raw text (gitleaks) consume blocks rather than the raw
// diff so that finding line numbers map back to the new file directly.
type AddedBlock struct {
	Path      string
	StartLine int
	Content   string
}

// WalkDiff parses a unified diff and returns one AddedBlock per
// contiguous run of '+' lines. Context lines, removals, hunk headers,
// and file boundaries all flush the current block. Blocks for files
// deleted to /dev/null are dropped.
func WalkDiff(diff []byte) []AddedBlock {
	var (
		blocks    []AddedBlock
		path      string
		newLine   int
		blockBuf  []string
		blockStart int
	)

	flush := func() {
		if len(blockBuf) == 0 || path == "" {
			blockBuf = blockBuf[:0]
			return
		}
		blocks = append(blocks, AddedBlock{
			Path:      path,
			StartLine: blockStart,
			Content:   strings.Join(blockBuf, "\n"),
		})
		blockBuf = blockBuf[:0]
	}

	scanner := bufio.NewScanner(bytes.NewReader(diff))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			path = ""
			newLine = 0
		case strings.HasPrefix(line, "+++ "):
			flush()
			path = parseNewPath(line[4:])
		case strings.HasPrefix(line, "--- "):
			// old-file path; ignored
		case strings.HasPrefix(line, "@@"):
			flush()
			newLine = parseHunkNewStart(line)
		case strings.HasPrefix(line, "\\ "):
			// "\ No newline at end of file"
		case strings.HasPrefix(line, "+"):
			if len(blockBuf) == 0 {
				blockStart = newLine
			}
			blockBuf = append(blockBuf, line[1:])
			newLine++
		case strings.HasPrefix(line, "-"):
			// removed line; new-file line counter does not advance
		case strings.HasPrefix(line, " "):
			flush()
			newLine++
		default:
			// Blank or no-marker lines inside a hunk are context. Real
			// git diffs prefix blank context lines with " ", but many
			// transports (web APIs, copy-paste, editors that strip
			// trailing whitespace) drop it — treat unprefixed lines
			// as context when we are inside a hunk so line numbering
			// stays correct.
			flush()
			if newLine > 0 {
				newLine++
			}
		}
	}
	flush()
	return blocks
}

// parseNewPath strips the b/ prefix from a "+++ b/path" line. Returns
// "" for /dev/null (file deletion).
func parseNewPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(raw, "b/") {
		return raw[2:]
	}
	return raw
}

// LocateInDiff finds the first occurrence of needle inside an added
// line of the diff and returns the post-image file and line number.
// Used by adapters whose upstream tool does not preserve source
// positions (notably `trufflehog stdin`).
func LocateInDiff(diff []byte, needle string) (string, int) {
	return locateInDiff(diff, needle)
}

func locateInDiff(diff []byte, needle string) (string, int) {
	if needle == "" {
		return "", 0
	}
	for _, block := range WalkDiff(diff) {
		for i, line := range strings.Split(block.Content, "\n") {
			if strings.Contains(line, needle) {
				return block.Path, block.StartLine + i
			}
		}
	}
	return "", 0
}

// parseHunkNewStart pulls the new-file starting line from a unified-diff
// hunk header "@@ -o,oc +n,nc @@". Returns 0 on malformed input; callers
// emit blocks only when a path is known, so a 0 here flushes harmlessly.
func parseHunkNewStart(line string) int {
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
