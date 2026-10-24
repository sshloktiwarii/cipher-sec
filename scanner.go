package main

import (
	"math"
	"regexp"
	"strings"
)

var (
	// Destructive commands that trigger outright rejection
	destructivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+`),
		regexp.MustCompile(`(?i)\bmkfs(\.[a-zA-Z0-9]+)?\s+`),
		regexp.MustCompile(`>\s*/dev/sd[a-z][0-9]?`),
		regexp.MustCompile(`>\s*/dev/nvme[0-9]+n[0-9]+`),
		regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`), // Fork bomb
		regexp.MustCompile(`(?i)\bdd\s+if=/dev/zero`),
		regexp.MustCompile(`(?i)\bchmod\s+(-R\s+)?777\s+/`),
	}

	// Secret credential patterns to redact
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                          // AWS Access Key ID
		regexp.MustCompile(`\bsk-[a-zA-Z0-9_-]{20,}\b`),                                     // OpenAI Secret Key
		regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),                                       // GitHub Personal Access Token
		regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`),                               // GitHub Fine-grained PAT
		regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z-]{10,}\b`),                              // Slack Token
		regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b`), // JWT
		regexp.MustCompile(`-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----[^\-]+-----END (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----`),
	}
)

const RedactedPlaceholder = "[REDACTED_BY_CIPHER_SEC]"

// InspectAndSanitize scans the payload for destructive commands and leaked credentials
func InspectAndSanitize(payload []byte) (sanitized []byte, blocked bool, reason string) {
	text := string(payload)

	// 1. Check for Destructive Commands
	for _, pattern := range destructivePatterns {
		if pattern.MatchString(text) {
			return nil, true, "Destructive system command detected in payload (" + pattern.String() + ")"
		}
	}

	// 2. Secret Redaction
	modified := text
	for _, pattern := range secretPatterns {
		modified = pattern.ReplaceAllString(modified, RedactedPlaceholder)
	}

	// 3. Scan for high-entropy hex/base64 tokens (> 32 chars)
	words := strings.FieldsFunc(modified, func(r rune) bool {
		return r == ' ' || r == '"' || r == '\'' || r == '\n' || r == '\t' || r == ','
	})

	for _, w := range words {
		cleaned := strings.TrimSpace(w)
		if len(cleaned) >= 32 && isLikelyToken(cleaned) {
			entropy := computeShannonEntropy(cleaned)
			if entropy > 4.6 {
				modified = strings.ReplaceAll(modified, cleaned, RedactedPlaceholder)
			}
		}
	}

	return []byte(modified), false, ""
}

func isLikelyToken(s string) bool {
	if strings.Contains(s, RedactedPlaceholder) {
		return false
	}
	// Check if composed predominantly of base64 or hex characters
	var validChars int
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '+' || r == '/' || r == '=' {
			validChars++
		}
	}
	return float64(validChars)/float64(len(s)) > 0.95
}

// computeShannonEntropy calculates bits of entropy per character
func computeShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
