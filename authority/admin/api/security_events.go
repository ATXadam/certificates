package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/smallstep/linkedca"
)

func logAdminSecurityEvent(ctx context.Context, event string, fields ...any) {
	attrs := make([]any, 0, len(fields)+4)
	attrs = append(attrs, "event", event, "timestamp", time.Now().UTC().Format(time.RFC3339Nano))
	if admin, ok := linkedca.AdminFromContext(ctx); ok && admin != nil {
		attrs = append(attrs, "admin_id", admin.Id, "admin_subject", admin.Subject)
	}
	attrs = append(attrs, fields...)
	slog.InfoContext(ctx, "ACME admin security event", attrs...)
}
