package security

import "strings"

// Sanitize neutralizes HTML/script-injection metacharacters so untrusted
// input is never reflected verbatim. Escaping is applied on output, not by
// mutating stored data.
func Sanitize(in string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
		"/", "&#47;",
		"\\", "&#92;",
		"\n", " ",
		"\r", " ",
		"\x00", "",
	)
	return r.Replace(in)
}

var sensitiveFragments = []string{"password", "passwd", "hash", "secret", "token", "cookie", "authorization"}

func isSensitiveField(field string) bool {
	f := strings.ToLower(field)
	for _, s := range sensitiveFragments {
		if strings.Contains(f, s) {
			return true
		}
	}
	return false
}

// Redact masks a value for logs/external output based on its field name.
//   - sensitive fields -> "***" (no length leaked)
//   - other values     -> first and last rune retained only when long enough,
//     otherwise "***"
func Redact(field, value string) string {
	if isSensitiveField(field) {
		return "***"
	}
	r := []rune(value)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 4:
		return "***"
	default:
		return string(r[0]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1])
	}
}

// SafeHeaders returns baseline defense-in-depth response headers.
func SafeHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Cache-Control":             "no-store",
	}
}
