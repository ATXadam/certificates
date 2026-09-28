package apiv1

import (
	"context"
	"testing"
)

func TestOrderAndAccountIDContext(t *testing.T) {
	ctx := context.Background()
	if got := OrderIDFromContext(ctx); got != "" {
		t.Fatalf("OrderIDFromContext(background) = %q, want empty", got)
	}
	if got := AccountIDFromContext(ctx); got != "" {
		t.Fatalf("AccountIDFromContext(background) = %q, want empty", got)
	}

	ctx = NewOrderIDContext(ctx, "order-1")
	ctx = NewAccountIDContext(ctx, "account-1")
	if got := OrderIDFromContext(ctx); got != "order-1" {
		t.Fatalf("OrderIDFromContext() = %q, want order-1", got)
	}
	if got := AccountIDFromContext(ctx); got != "account-1" {
		t.Fatalf("AccountIDFromContext() = %q, want account-1", got)
	}
}
