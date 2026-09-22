package api

import (
	"context"
	"testing"

	"github.com/smallstep/certificates/acme"
)

func TestHasNonEmptyACMEPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *acme.Policy
		want   bool
	}{
		{name: "nil EAB"},
		{name: "empty policy", policy: &acme.Policy{}},
		{name: "wildcard only", policy: &acme.Policy{X509: acme.X509Policy{AllowWildcardNames: true}}},
		{name: "deny only", policy: &acme.Policy{X509: acme.X509Policy{Denied: acme.PolicyNames{DNSNames: []string{"bad.example"}}}}},
		{name: "IP only", policy: &acme.Policy{X509: acme.X509Policy{Allowed: acme.PolicyNames{IPRanges: []string{"192.0.2.0/24"}}}}},
		{name: "positive DNS allow", policy: &acme.Policy{X509: acme.X509Policy{Allowed: acme.PolicyNames{DNSNames: []string{"example.com"}}}}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var eak *acme.ExternalAccountKey
			if tt.policy != nil {
				eak = &acme.ExternalAccountKey{Policy: tt.policy}
			}
			if got := hasNonEmptyACMEPolicy(eak); got != tt.want {
				t.Fatalf("hasNonEmptyACMEPolicy() = %v, want %v", got, tt.want)
			}
		})
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

func TestTrustedPolicyWildcardSemantics(t *testing.T) {
	for _, tt := range []struct {
		name           string
		allowWildcard  bool
		wantWildcardOK bool
	}{
		{name: "wildcard disabled", wantWildcardOK: false},
		{name: "wildcard enabled", allowWildcard: true, wantWildcardOK: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := newACMEPolicyEngine(&acme.ExternalAccountKey{Policy: &acme.Policy{X509: acme.X509Policy{
				Allowed: acme.PolicyNames{DNSNames: []string{"*.revsolns.net"}}, AllowWildcardNames: tt.allowWildcard,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			err = isIdentifierAllowed(engine, acme.Identifier{Type: acme.DNS, Value: "*.revsolns.net"})
			if (err == nil) != tt.wantWildcardOK {
				t.Fatalf("wildcard authorization error = %v, want allowed = %v", err, tt.wantWildcardOK)
			}
		})
	}
}

func TestTrustedPolicyRejectsMixedOrder(t *testing.T) {
	engine, err := newACMEPolicyEngine(&acme.ExternalAccountKey{Policy: &acme.Policy{X509: acme.X509Policy{
		Allowed: acme.PolicyNames{DNSNames: []string{"*.revsolns.net", "*.incus.revsolns.net"}}, AllowWildcardNames: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []acme.Identifier{
		{Type: acme.DNS, Value: "*.revsolns.net"},
		{Type: acme.DNS, Value: "*.incus.revsolns.net"},
		{Type: acme.DNS, Value: "*.unauthorized.example"},
	} {
		if err := isIdentifierAllowed(engine, identifier); identifier.Value == "*.unauthorized.example" && err == nil {
			t.Fatalf("unauthorized identifier %q was allowed", identifier.Value)
		}
	}
}
