// Package redact masks credential bodies for use in API responses and
// non-audit logs. Raw matches must never enter either; only Preview()
// output is safe to surface outside the audit-log opt-in path.
package redact

import (
	"net/url"
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

// Scrub replaces any verbatim occurrence of secret in text with the
// redacted Preview(secret). The LLM's free-text reason sometimes quotes
// the matched value in full ("the value 'sOqY...Zx9y' is a literal API
// key"); this keeps the raw secret out of the reason the same way
// Preview keeps it out of match previews. A blank secret, or a text
// that doesn't contain it, is returned unchanged.
//
// This catches verbatim quoting, which is the observed leak vector. It
// does not catch a secret the model reformatted (re-cased, partially
// quoted); the prompt also instructs the model not to quote values, and
// the match preview remains the only value ever surfaced deliberately.
func Scrub(text, secret string) string {
	if secret == "" || !strings.Contains(text, secret) {
		return text
	}
	return strings.ReplaceAll(text, secret, Preview(secret))
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
