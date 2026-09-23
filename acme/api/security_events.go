package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"
)

// logSecurityEvent emits structured ACME security audit events. Callers must
// pass only identifiers and policy outcomes; request bodies, EAB JWS values,
// signatures, and credentials must never be included.
func logSecurityEvent(ctx context.Context, event string, fields ...any) {
	attrs := make([]any, 0, len(fields)+4)
	attrs = append(attrs, "event", event, "timestamp", time.Now().UTC().Format(time.RFC3339Nano))
	attrs = append(attrs, fields...)
	slog.InfoContext(ctx, "ACME security event", attrs...)
}

func csrSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
