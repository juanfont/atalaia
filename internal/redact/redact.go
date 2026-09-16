// Package redact masks credential bodies for use in API responses and
// non-audit logs. Raw matches must never enter either; only Preview()
// output is safe to surface outside the audit-log opt-in path.
package redact

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const mask = "****"

// Preview returns a redacted view of a match. URL credentials with a
// userinfo block are reshaped to "scheme://****:****@host/path";
// everything else keeps a small head/tail and masks the middle.
func Preview(match string) string {
	if match == "" {
		return ""
	}
	if r := previewURL(match); r != "" {
		return r
	}
	if parts := mysqlDSN.FindStringSubmatch(match); parts != nil {
		return mask + ":" + mask + "@" + parts[3]
	}
	return previewGeneric(match)
}

func previewURL(match string) string {
	u, err := url.Parse(match)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User == nil {
		return ""
	}
	// Build the redacted form manually: net/url percent-encodes the
	// mask characters when round-tripped through Userinfo.
	tail := u.Host
	if u.Path != "" {
		tail += u.Path
	}
	if u.RawQuery != "" {
		tail += "?" + u.RawQuery
	}
	return u.Scheme + "://" + mask + ":" + mask + "@" + tail
}

// Scrub masks the complete match and credential components of known connection
// strings. A model may quote just a URL password in its reason even when its
// candidate is the whole URL. Both encoded source spelling and decoded userinfo
// are scrubbed. This does not change grounding or permit decoded candidates.
func Scrub(text, secret string) string {
	if secret == "" {
		return text
	}
	text = strings.ReplaceAll(text, secret, Preview(secret))
	parts := credentialParts(secret)
	sort.Slice(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	for _, part := range parts {
		if part != "" {
			text = strings.ReplaceAll(text, part, mask)
		}
	}
	return text
}

// mysqlDSN is the user:password@tcp(...) or user:password@unix(...) form.
// Greedy password matching preserves embedded @ characters.
var mysqlDSN = regexp.MustCompile(`^([^:@/]*):(.*)@((?:tcp|unix)\(.*)$`)

func credentialParts(secret string) []string {
	if u, err := url.Parse(secret); err == nil && u.Scheme != "" && u.Host != "" && u.User != nil {
		password, _ := u.User.Password()
		parts := []string{u.User.Username(), password}
		// Userinfo.String() may normalize percent escapes. Extract the
		// original authority too so source spellings are scrubbed exactly.
		_, authority, ok := strings.Cut(secret, "://")
		if ok {
			if end := strings.IndexAny(authority, "/?#"); end >= 0 {
				authority = authority[:end]
			}
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				username, rawPassword, _ := strings.Cut(authority[:at], ":")
				parts = append(parts, username, rawPassword)
			}
		}
		return parts
	}
	if parts := mysqlDSN.FindStringSubmatch(secret); parts != nil {
		return parts[1:3]
	}
	return nil
}

func previewGeneric(match string) string {
	const head, tail = 4, 4
	if len(match) <= head+tail {
		return mask
	}
	var b strings.Builder
	b.Grow(head + tail + len(mask))
	b.WriteString(match[:head])
	b.WriteString(mask)
	b.WriteString(match[len(match)-tail:])
	return b.String()
}
