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
		MgetID:         func() string { return "generated-admin-id" },
		MgetIDForToken: func() string { return "acme/acme" },
		MgetName:       func() string { return "acme" },
	})

	if got, err := acmeProvisionerID(ctx); err != nil || got != "acme/acme" {
		t.Fatalf("acmeProvisionerID() = %q, want %q", got, "acme/acme")
	}
}

func TestAcmeProvisionerIDPreservesExplicitRuntimeIdentity(t *testing.T) {
	adminRecord := &linkedca.Provisioner{Id: "generated-admin-id", Name: "acme"}
	ctx := linkedca.NewContextWithProvisioner(context.Background(), adminRecord)
	ctx = acme.NewProvisionerContext(ctx, &acme.MockProvisioner{
		MgetID:         func() string { return "database-id" },
		MgetIDForToken: func() string { return "acme/internal" },
	})

	if got, err := acmeProvisionerID(ctx); err != nil || got != "acme/internal" {
		t.Fatalf("acmeProvisionerID() = %q, want %q; err=%v", got, "acme/internal", err)
	}
}

func TestAcmeProvisionerIDLegacyContextFallback(t *testing.T) {
	ctx := linkedca.NewContextWithProvisioner(context.Background(), &linkedca.Provisioner{
		Id:   "generated-linkedca-id",
		Name: "acme",
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_ACME{ACME: &linkedca.ACMEProvisioner{}},
		},
	})
	if got, err := acmeProvisionerID(ctx); err != nil || got != "acme/acme" {
		t.Fatalf("acmeProvisionerID() = %q, want %q; err=%v", got, "acme/acme", err)
	}
}

func TestAcmeProvisionerIDRejectsNonACMEFallback(t *testing.T) {
	ctx := linkedca.NewContextWithProvisioner(context.Background(), &linkedca.Provisioner{
		Id:   "generated-linkedca-id",
		Name: "admin",
	})
	if got, err := acmeProvisionerID(ctx); err == nil || got != "" {
		t.Fatalf("acmeProvisionerID() = %q, %v; want non-ACME error", got, err)
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
