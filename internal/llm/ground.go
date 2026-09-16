package llm

import (
	"regexp"
	"strings"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/metrics"
	"github.com/juanfont/atalaia/internal/redact"
)

// minCandidateChars rejects values too short to be a credential. Below
// this the substring search matches half the diff.
const minCandidateChars = 6

// DeepCandidate is one claim from the deep read, before grounding. The
// model supplies no file, no line, and no id: it has no way to express
// a location, so it has no way to hallucinate one.
type DeepCandidate struct {
	Value      string
	Kind       string
	Confidence float64
	Reason     string
}

// Discovery is a grounded candidate: a value the model claimed and the
// diff confirmed, with a position derived from the diff itself.
//
// Match holds the raw value for the audit path only. It must never
// reach an API response or a non-audit log; callers copy MatchPreview.
type Discovery struct {
	ID           string
	File         string
	Line         int
	Match        string
	MatchPreview string
	Kind         string
	Confidence   float64
	Reason       string
}

// GroundStats is the per-request accounting the API layer reports.
type GroundStats struct {
	Candidates int
	Discovered int
	Ungrounded int
	Collisions int
}

// Ground turns model claims into locatable discoveries and discards
// everything else. It is the anti-hallucination gate: a value the model
// invented is not in the diff, so it cannot be located, so it cannot be
// reported.
//
// taken is the deduplicated detector finding set. Anything already
// covered there belongs to verdicts[], the authoritative channel, and is
// dropped here so the two arrays stay disjoint.
// GroundDecision is an evaluation trace. It contains no credential bytes.
type GroundDecision struct {
	Candidate int
	Outcome   string
	File      string
	Line      int
}

func GroundWithTrace(diff []byte, cands []DeepCandidate, taken []detector.DedupedFinding) ([]Discovery, GroundStats, []GroundDecision) {
	var decisions []GroundDecision
	out, stats := ground(diff, cands, taken, func(d GroundDecision) { decisions = append(decisions, d) })
	return out, stats, decisions
}

func Ground(diff []byte, cands []DeepCandidate, taken []detector.DedupedFinding) ([]Discovery, GroundStats) {
	return ground(diff, cands, taken, nil)
}

func ground(diff []byte, cands []DeepCandidate, taken []detector.DedupedFinding, trace func(GroundDecision)) ([]Discovery, GroundStats) {
	stats := GroundStats{Candidates: len(cands)}
	metrics.DeepCandidatesTotal.Add(float64(len(cands)))

	seen := make(map[string]bool, len(cands))
	out := make([]Discovery, 0, len(cands))

	for i, c := range cands {
		func() {
			decision := GroundDecision{Candidate: i, Outcome: "rejected"}
			defer func() {
				if trace != nil {
					trace(decision)
				}
			}()

			// Grounding proves existence, not that a credential is live.
			// Honor the model's explicit synthetic-test classification.
			if c.Kind == KindTestData {
				decision.Outcome = "test_data"
				return
			}
			needle, ok := groundingNeedle(diff, c)
			if !ok {
				decision.Outcome = "invalid_or_reference"
				stats.Ungrounded++
				metrics.DeepUngroundedTotal.Inc()
				return
			}

			// An assignment-shaped candidate ("KEY=value", "key: value")
			// is located by the full text the model returned, which pins
			// the line precisely, but the secret it describes is the
			// value. Everything downstream (length, placeholder, sentinel,
			// id, preview) must see the value, or "POSTGRES_PASSWORD=test"
			// sails through as a 22-character secret and the preview
			// redacts the key name.
			var file string
			var line int
			var match string
			if key, val, isAssign := assignmentValue(needle); isAssign {
				if !isSecretKey(key, val) || isPlaceholder(val) || len(val) < minCandidateChars {
					decision.Outcome = "non_secret_assignment"
					return
				}
				file, line, _ = locate(diff, needle)
				if file == "" {
					file, line, _ = locate(diff, val)
				}
				match = val
			} else {
				if isPlaceholder(needle) {
					decision.Outcome = "placeholder"
					return
				}
				file, line, match = locate(diff, needle)
			}
			if file == "" {
				decision.Outcome = "not_found"
				stats.Ungrounded++
				metrics.DeepUngroundedTotal.Inc()
				return
			}

			// The sentinel table that auto-dismisses documented sample keys
			// in the other channel applies here too. A cold-discovered
			// AKIAIOSFODNN7EXAMPLE is the same non-secret.
			if _, isSentinel := classifySentinel(match); isSentinel {
				decision.Outcome = "sentinel"
				return
			}

			// A bare variable NAME grounds happily, because it really is in
			// the line: "PG_PASSWORD" is a substring of "${PG_PASSWORD}".
			// isReference cannot catch that, since the value the model
			// returned carries no $ or braces of its own. Look at where it
			// actually landed instead: if every occurrence in the line sits
			// inside a $VAR or ${VAR} reference, it names a secret rather
			// than being one.
			if txt := addedLineText(diff, file, line); txt != "" && onlyInVarReference(txt, match) {
				decision.Outcome = "reference"
				return
			}

			decision.File, decision.Line = file, line
			id := detector.FindingID(detector.Finding{File: file, Line: line, Match: match})
			if seen[id] {
				decision.Outcome = "duplicate"
				return
			}
			if collidesWithVerdict(taken, file, line, match) {
				decision.Outcome = "detector_overlap"
				stats.Collisions++
				return
			}
			seen[id] = true

			kind := c.Kind
			if kind != "private_key" {
				kind = "credential"
			}

			out = append(out, Discovery{
				ID:           id,
				File:         file,
				Line:         line,
				Match:        match,
				MatchPreview: redact.Preview(match),
				Kind:         kind,
				Confidence:   c.Confidence,
				Reason:       redact.Scrub(c.Reason, match),
			})
			decision.Outcome = "discovered"
			stats.Discovered++
			metrics.DeepDiscoveriesTotal.Inc()
		}()
	}

	return out, stats
}

// groundingNeedle picks the string to search the diff for, and rejects
// candidates not worth searching.
//
// Private key material grounds on its BEGIN header rather than the
// whole value: a PEM block spans dozens of lines, LocateInDiff searches
// line by line, and no small model reproduces a key body verbatim.
// Requiring the BEGIN line specifically also rejects a candidate that
// is only the END delimiter, which locates fine but is a marker, not a
// credential, and would report the same key a second time.
func groundingNeedle(diff []byte, c DeepCandidate) (string, bool) {
	v := c.Value
	if c.Kind == "private_key" {
		v = pemHeaderLine(v)
	} else if (strings.Contains(v, "-----BEGIN ") || strings.Contains(v, "-----END ")) && pemHeaderLine(v) == "" {
		// A public PEM object cannot become secret by changing its kind.
		return "", false
	}
	v = strings.TrimSpace(v)

	if len(v) < minCandidateChars {
		return "", false
	}
	if isReference(v) && !quotedCallLiteral(diff, v) {
		return "", false
	}
	return v, true
}

// quotedCallLiteral distinguishes function-shaped password bytes from code.
// It only rescues a complete quoted literal or a password component in a
// quoted user:password@ connection string. The first grounded occurrence must
// supply that evidence. Arbitrary quoted expressions and interpolations do not
// qualify, and all non-call reference guards remain in force.
func quotedCallLiteral(diff []byte, value string) bool {
	if !functionReferenceRE.MatchString(value) || !strings.HasSuffix(value, ")") ||
		strings.ContainsAny(value, "$\\{}") || strings.HasPrefix(value, "process.env.") || strings.HasPrefix(value, "os.environ") {
		return false
	}
	file, line := detector.LocateInDiff(diff, value)
	if file == "" {
		return false
	}
	text := addedLineText(diff, file, line)
	first := strings.Index(text, value)
	for i := 0; i < len(text); i++ {
		quote := text[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		start := i + 1
		for i++; i < len(text); i++ {
			if text[i] == '\\' {
				i++
				continue
			}
			if text[i] != quote {
				continue
			}
			literal := text[start:i]
			if first >= start && first+len(value) <= i && !strings.ContainsAny(literal, "$\\{}") {
				if literal == value {
					return true
				}
				// Includes URI userinfo and the common MySQL user:pass@tcp DSN.
				if at := strings.Index(literal, ":"+value+"@"); at > 0 {
					return true
				}
			}
			break
		}
	}
	return false
}

// locate finds the value in an added line of the diff, retrying once
// with a normalized form. Models re-quote and re-punctuate what they
// copy; one normalization pass recovers those without loosening the
// gate into a fuzzy match. It returns the form that actually matched,
// so the id and preview describe what is really in the diff.
func locate(diff []byte, needle string) (file string, line int, match string) {
	if f, l := detector.LocateInDiff(diff, needle); f != "" {
		return f, l, needle
	}
	norm := normalizeCandidate(needle)
	if norm != needle && len(norm) >= minCandidateChars {
		if f, l := detector.LocateInDiff(diff, norm); f != "" {
			return f, l, norm
		}
	}
	return "", 0, ""
}

// normalizeCandidate strips the decoration a model adds around a value
// it copied: surrounding quotes or backticks, and trailing punctuation.
func normalizeCandidate(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ",;")
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if first == last && (first == '"' || first == '\'' || first == '`') {
			s = s[1 : len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}

// isReference rejects values that name a secret instead of being one.
// There are no secret bytes in a reference, so reporting one can only
// be noise.
func isReference(v string) bool {
	// A basic-auth pair can have a literal username and a runtime-only
	// password. The username does not turn that reference into a secret.
	if basicAuthReferenceRE.MatchString(normalizeCandidate(v)) {
		return true
	}
	switch {
	case strings.HasPrefix(v, "$"):
		return true
	case strings.Contains(v, "${"):
		return true
	// A call or lookup: os.Getenv("X"), config.get(...), vault.read(...)
	case functionReferenceRE.MatchString(v) && strings.HasSuffix(strings.TrimSpace(v), ")"):
		return true
	case strings.HasPrefix(v, "process.env."), strings.HasPrefix(v, "os.environ"):
		return true
	}
	return false
}

var functionReferenceRE = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*\s*\(`)

var basicAuthReferenceRE = regexp.MustCompile(`^[^:\s]+:\$[A-Za-z_][A-Za-z0-9_]*$`)

// collidesWithVerdict reports whether a detector finding already covers
// this value. Id equality alone is not enough: the id embeds the match,
// so a detector that matched the bare key body and a model that
// returned the whole assignment produce different ids for the same
// secret. Same file and line plus either value containing the other is
// the same finding, and verdicts[] wins.
func collidesWithVerdict(taken []detector.DedupedFinding, file string, line int, needle string) bool {
	for _, d := range taken {
		if d.File != file || d.Line != line {
			continue
		}
		if strings.Contains(d.Match, needle) || strings.Contains(needle, d.Match) {
			return true
		}
	}
	return false
}

// addedLineText returns the text of one added line, located the same
// way LocateInDiff locates a match.
func addedLineText(diff []byte, file string, line int) string {
	for _, b := range detector.WalkDiff(diff) {
		if b.Path != file {
			continue
		}
		lines := strings.Split(b.Content, "\n")
		if idx := line - b.StartLine; idx >= 0 && idx < len(lines) {
			return lines[idx]
		}
	}
	return ""
}

// onlyInVarReference reports whether every occurrence of needle in line
// sits inside a shell or template variable reference. One bare
// occurrence is enough to treat the value as a literal.
func onlyInVarReference(line, needle string) bool {
	found := false
	for i := 0; ; {
		j := strings.Index(line[i:], needle)
		if j < 0 {
			break
		}
		pos := i + j
		found = true
		if !varRefAt(line, pos) {
			return false
		}
		i = pos + 1
		if i >= len(line) {
			break
		}
	}
	return found
}

// varRefAt reports whether the token starting at pos is introduced by
// $ or ${.
func varRefAt(line string, pos int) bool {
	if pos >= 2 && line[pos-2] == '$' && line[pos-1] == '{' {
		return true
	}
	if pos >= 1 && line[pos-1] == '$' {
		return true
	}
	return false
}

// assignmentRE matches "KEY=value", "key: value" and the common
// declaration prefixes ("export KEY=", "const key =", "let", "var",
// "val") with an identifier-shaped key. Anything else is treated as a
// bare value.
var assignmentRE = regexp.MustCompile(`^\s*(?:(?:export|const|let|var|val)\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:=|:\s)\s*(.*)$`)

// assignmentValue splits an assignment-shaped candidate into key and
// value. The value is unquoted and stripped of trailing punctuation the
// same way a bare candidate is. Returns false for anything that is not
// assignment-shaped, or whose value is empty.
func assignmentValue(s string) (key, val string, ok bool) {
	m := assignmentRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	val = normalizeCandidate(m[2])
	if val == "" {
		return "", "", false
	}
	return m[1], val, true
}

// nonSecretKeySuffixes are assignment keys whose values are, by their
// own name, not credentials: identities, locations, and addresses. The
// model reported POSTGRES_USER=test as "a plain-text username", which
// is correct and not a leak.
var nonSecretKeySuffixes = []string{
	"USER", "USERNAME", "USERID", "USER_ID", "LOGIN", "EMAIL",
	"HOST", "HOSTNAME", "PORT", "DOMAIN", "REGION", "ZONE", "BUCKET",
	"DB", "DATABASE", "DBNAME", "DB_NAME", "SCHEMA", "TABLE",
	"CLIENT_ID", "APP_ID", "ACCOUNT_ID", "PROJECT_ID", "TENANT_ID", "ORG_ID",
	"NAME", "ENV", "ENVIRONMENT", "MODE", "LEVEL", "VERSION",
}

// isSecretKey reports whether an assignment key could name a secret.
// A value that is itself a URL with embedded credentials is a secret
// under any key, including DATABASE_URL.
func isSecretKey(key, val string) bool {
	if urlWithCredentials(val) {
		return true
	}
	k := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
	for _, suffix := range nonSecretKeySuffixes {
		if k == suffix || strings.HasSuffix(k, "_"+suffix) {
			return false
		}
	}
	return true
}

// urlWithCredentials reports whether v looks like scheme://user:pass@host.
func urlWithCredentials(v string) bool {
	i := strings.Index(v, "://")
	if i < 0 {
		return false
	}
	rest := v[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return false
	}
	return strings.Contains(rest[:at], ":")
}

// urlPassword returns the password segment of scheme://user:pass@host,
// or "" when there is none.
func urlPassword(v string) string {
	i := strings.Index(v, "://")
	if i < 0 {
		return ""
	}
	rest := v[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return ""
	}
	userinfo := rest[:at]
	if c := strings.Index(userinfo, ":"); c >= 0 {
		return userinfo[c+1:]
	}
	return ""
}

// placeholderWords are values that are filler by convention. Exact
// match after lowercasing. Deliberately short: a real weak password
// like hunter2 is still a leak, so this is for words nobody uses as a
// password, only as a stand-in for one.
var placeholderWords = map[string]bool{
	"test": true, "testing": true, "example": true, "sample": true,
	"changeme": true, "change-me": true, "change_me": true,
	"placeholder": true, "dummy": true, "fake": true,
	"password": true, "passwd": true, "secret": true, "token": true,
	"todo": true, "fixme": true, "tbd": true,
	"none": true, "null": true, "nil": true, "empty": true, "unset": true,
	"redacted": true, "removed": true,
	"root-token": true, "dev-token": true, "dev-only-token": true, "test-token": true,
	"your-token": true, "your-key": true, "your-secret": true, "your-password": true,
}

// isPlaceholder reports whether a value is template filler rather than
// a credential: a known placeholder word, a <template> or {{template}}
// marker, a your_/my_/example_ prefix, or one repeated character.
func isPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	// For a URL with embedded credentials, the password is the secret.
	// Judge that, not the whole URL: "example.internal" in the host is
	// not filler, and "test" as the password is.
	if urlWithCredentials(v) {
		return isPlaceholder(urlPassword(v))
	}
	lower := strings.ToLower(v)
	if placeholderWords[lower] {
		return true
	}
	if (strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">")) ||
		(strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}")) ||
		(strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") && len(v) > 2) {
		return true
	}
	for _, p := range []string{"your-", "your_", "my-", "my_", "example-", "example_", "replace-", "replace_", "insert-", "insert_"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	for _, w := range []string{"example", "placeholder", "changeme", "dummy"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	// One repeated character: xxxxxxxx, ********, 00000000.
	if len(v) >= 4 && strings.Count(v, v[:1]) == len(v) {
		return true
	}
	return false
}

// pemHeaderLine returns the first recognized private-key BEGIN line in s, or
// "" when there is none. A private-key candidate without a BEGIN line
// is not groundable as key material.
func pemHeaderLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		switch t {
		case "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
			"-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----":
			return t
		}
	}
	return ""
}
