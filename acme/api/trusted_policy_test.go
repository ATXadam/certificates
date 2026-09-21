package api

import (
	"context"
	"testing"

	"github.com/smallstep/certificates/acme"
)

func TestHasNonEmptyACMEPolicy(t *testing.T) {
	if hasNonEmptyACMEPolicy(nil) {
		t.Fatal("nil EAB must not be trusted")
	}
	if hasNonEmptyACMEPolicy(&acme.ExternalAccountKey{Policy: &acme.Policy{}}) {
		t.Fatal("empty EAB policy must not be trusted")
	}
	if !hasNonEmptyACMEPolicy(&acme.ExternalAccountKey{Policy: &acme.Policy{
		X509: acme.X509Policy{Allowed: acme.PolicyNames{DNSNames: []string{"example.com"}}},
	}}) {
		t.Fatal("configured EAB policy must be trusted")
	}
}

func TestNewAuthorizationWithTrust(t *testing.T) {
	db := &acme.MockDB{MockCreateAuthorization: func(_ context.Context, az *acme.Authorization) error {
		az.ID = "authz-id"
		return nil
	}}
	ctx := acme.NewDatabaseContext(context.Background(), db)
	az := &acme.Authorization{
		AccountID:  "account-id",
		Identifier: acme.Identifier{Type: acme.DNS, Value: "*.example.com"},
	}
	if err := newAuthorizationWithTrust(ctx, az, true); err != nil {
		t.Fatalf("newAuthorizationWithTrust() error = %v", err)
	}
	if az.Status != acme.StatusValid {
		t.Fatalf("status = %s, want valid", az.Status)
	}
	if !az.Wildcard || az.Identifier.Value != "example.com" {
		t.Fatalf("authorization identifier = %#v, wildcard = %v", az.Identifier, az.Wildcard)
	}
	if len(az.Challenges) != 0 {
		t.Fatalf("trusted authorization has %d challenges, want none", len(az.Challenges))
	}
}
