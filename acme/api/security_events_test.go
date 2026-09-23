package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLogSecurityEventUsesStructuredSafeFields(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	logSecurityEvent(context.Background(), "downstream_order_created",
		"local_order_id", "order-1", "account_id", "account-1",
		"provisioner_id", "acme/acme", "result", "success",
	)
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"event": "downstream_order_created", "local_order_id": "order-1",
		"account_id": "account-1", "provisioner_id": "acme/acme", "result": "success",
	} {
		if event[key] != want {
			t.Errorf("event[%q] = %v, want %q", key, event[key], want)
		}
	}
	if _, ok := event["timestamp"]; !ok {
		t.Fatal("event has no UTC timestamp")
	}
}
