package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// bearerAuth wraps a handler, requiring `Authorization: Bearer <token>`
// when token is non-empty. An empty token short-circuits to "no auth
// required" — the explicit opt-in pattern keeps zero-config dev
// deployments running without secrets.
//
// Constant-time compare protects against timing leaks if a future
// integration probes character-by-character.
func bearerAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return next
	}
	want := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := extractBearer(r.Header.Get("Authorization"))
		if !ok || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="atalaia"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	}
}

func extractBearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}
