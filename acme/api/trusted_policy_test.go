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

func TestTrustedPolicySANRegressionMatrix(t *testing.T) {
	tests := []struct {
		name         string
		policy       *acme.Policy
		identifiers  []acme.Identifier
		wantAllAllow bool
	}{
		{
			name: "explicit DNS plus wildcard disabled rejects wildcard",
			policy: &acme.Policy{X509: acme.X509Policy{
				Allowed: acme.PolicyNames{DNSNames: []string{"revsolns.net"}},
			}},
			identifiers:  []acme.Identifier{{Type: acme.DNS, Value: "*.revsolns.net"}},
			wantAllAllow: false,
		},
		{
			name: "explicit DNS plus wildcard enabled allows wildcard",
			policy: &acme.Policy{X509: acme.X509Policy{
				Allowed: acme.PolicyNames{DNSNames: []string{"*.revsolns.net"}}, AllowWildcardNames: true,
			}},
			identifiers:  []acme.Identifier{{Type: acme.DNS, Value: "*.revsolns.net"}},
			wantAllAllow: true,
		},
		{
			name: "two explicitly allowed wildcard SANs",
			policy: &acme.Policy{X509: acme.X509Policy{
				Allowed: acme.PolicyNames{DNSNames: []string{"*.revsolns.net", "*.incus.revsolns.net"}}, AllowWildcardNames: true,
			}},
			identifiers: []acme.Identifier{
				{Type: acme.DNS, Value: "*.revsolns.net"},
				{Type: acme.DNS, Value: "*.incus.revsolns.net"},
			},
			wantAllAllow: true,
		},
		{
			name: "mixed authorized and unauthorized SANs rejects order",
			policy: &acme.Policy{X509: acme.X509Policy{
				Allowed: acme.PolicyNames{DNSNames: []string{"*.revsolns.net"}}, AllowWildcardNames: true,
			}},
			identifiers: []acme.Identifier{
				{Type: acme.DNS, Value: "*.revsolns.net"},
				{Type: acme.DNS, Value: "*.unauthorized.revsolns.net"},
			},
			wantAllAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := newACMEPolicyEngine(&acme.ExternalAccountKey{Policy: tt.policy})
			if err != nil {
				t.Fatal(err)
			}
			allAllowed := true
			for _, identifier := range tt.identifiers {
				if err := isIdentifierAllowed(engine, identifier); err != nil {
					allAllowed = false
				}
			}
			if allAllowed != tt.wantAllAllow {
				t.Fatalf("all identifiers allowed = %v, want %v", allAllowed, tt.wantAllAllow)
			}
		})
	}
}

func TestValidateCurrentOrderPolicyUsesWholeOrder(t *testing.T) {
	var got []string
	ca := &mockCA{MockAreSANsallowed: func(_ context.Context, sans []string) error {
		got = append([]string(nil), sans...)
		return nil
	}}
	o := &acme.Order{Identifiers: []acme.Identifier{
		{Type: acme.DNS, Value: "*.revsolns.net"},
		{Type: acme.DNS, Value: "*.incus.revsolns.net"},
	}}
	if err := validateCurrentOrderPolicy(context.Background(), o, &acme.MockDB{}, ca, &fakeProvisioner{}); err != nil {
		t.Fatalf("validateCurrentOrderPolicy() error = %v", err)
	}
	if len(got) != 2 || got[0] != "*.revsolns.net" || got[1] != "*.incus.revsolns.net" {
		t.Fatalf("authority policy saw %v, want the complete order SAN set", got)
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
