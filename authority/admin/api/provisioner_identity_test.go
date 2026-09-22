package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/acme"
)

func TestAcmeProvisionerIDUsesRuntimeIdentity(t *testing.T) {
	adminRecord := &linkedca.Provisioner{Id: "generated-admin-id", Name: "acme"}

	ctx := linkedca.NewContextWithProvisioner(context.Background(), adminRecord)
	ctx = acme.NewProvisionerContext(ctx, &acme.MockProvisioner{
		MgetID:   func() string { return "acme/acme" },
		MgetName: func() string { return "acme" },
	})

	if got := acmeProvisionerID(ctx); got != "acme/acme" {
		t.Fatalf("acmeProvisionerID() = %q, want %q", got, "acme/acme")
	}
}

func TestAcmeProvisionerIDPreservesExplicitRuntimeIdentity(t *testing.T) {
	adminRecord := &linkedca.Provisioner{Id: "generated-admin-id", Name: "acme"}
	ctx := linkedca.NewContextWithProvisioner(context.Background(), adminRecord)
	ctx = acme.NewProvisionerContext(ctx, &acme.MockProvisioner{
		MgetID: func() string { return "explicit-acme-id" },
	})

	if got := acmeProvisionerID(ctx); got != "explicit-acme-id" {
		t.Fatalf("acmeProvisionerID() = %q, want %q", got, "explicit-acme-id")
	}
}

func TestAcmeProvisionerIDLegacyContextFallback(t *testing.T) {
	ctx := linkedca.NewContextWithProvisioner(context.Background(), &linkedca.Provisioner{Id: "legacy-id"})
	if got := acmeProvisionerID(ctx); got != "legacy-id" {
		t.Fatalf("acmeProvisionerID() fallback = %q, want %q", got, "legacy-id")
	}
}

func TestCreateExternalAccountKeyUsesRuntimeProvisionerID(t *testing.T) {
	var gotProvisionerID string
	db := &acme.MockDB{
		MockCreateExternalAccountKey: func(_ context.Context, provisionerID, reference string) (*acme.ExternalAccountKey, error) {
			gotProvisionerID = provisionerID
			return &acme.ExternalAccountKey{ID: "eab-id", ProvisionerID: provisionerID, Reference: reference}, nil
		},
	}
	ctx := linkedca.NewContextWithProvisioner(context.Background(), &linkedca.Provisioner{Id: "generated-admin-id", Name: "acme"})
	ctx = acme.NewProvisionerContext(ctx, &acme.MockProvisioner{MgetID: func() string { return "acme/acme" }})
	ctx = acme.NewDatabaseContext(ctx, db)

	req := httptest.NewRequest(http.MethodPost, "/admin/acme/eab/acme", bytes.NewBufferString(`{"reference":"test"}`)).WithContext(ctx)
	recorder := httptest.NewRecorder()
	NewACMEAdminResponder().CreateExternalAccountKey(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if gotProvisionerID != "acme/acme" {
		t.Fatalf("created EAB provisioner ID = %q, want %q", gotProvisionerID, "acme/acme")
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["provisioner"] != "acme/acme" {
		t.Fatalf("response provisioner = %v, want %q", response["provisioner"], "acme/acme")
	}
}
