package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/acme/wire"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

// NewOrderRequest represents the body for a NewOrder request.
type NewOrderRequest struct {
	Identifiers []acme.Identifier `json:"identifiers"`
	NotBefore   time.Time         `json:"notBefore,omitempty"`
	NotAfter    time.Time         `json:"notAfter,omitempty"`
}

// Validate validates a new-order request body.
func (n *NewOrderRequest) Validate() error {
	if len(n.Identifiers) == 0 {
		return acme.NewError(acme.ErrorMalformedType, "identifiers list cannot be empty")
	}
	for _, id := range n.Identifiers {
		switch id.Type {
		case acme.IP:
			if net.ParseIP(id.Value) == nil {
				return acme.NewError(acme.ErrorMalformedType, "invalid IP address: %s", id.Value)
			}
		case acme.DNS:
			value, _ := trimIfWildcard(id.Value)
			if _, err := x509util.SanitizeName(value); err != nil {
				return acme.NewError(acme.ErrorMalformedType, "invalid DNS name: %s", id.Value)
			}
		case acme.PermanentIdentifier:
			if id.Value == "" {
				return acme.NewError(acme.ErrorMalformedType, "permanent identifier cannot be empty")
			}
		case acme.WireUser, acme.WireDevice:
			// validation of Wire identifiers is performed in `validateWireIdentifiers`, but
			// marked here as known and supported types.
			continue
		default:
			return acme.NewError(acme.ErrorMalformedType, "identifier type unsupported: %s", id.Type)
		}
	}

	if err := n.validateWireIdentifiers(); err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "failed validating Wire identifiers")
	}

	// TODO(hs): add some validations for DNS domains?
	// TODO(hs): combine the errors from this with allow/deny policy, like example error in https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1

	return nil
}

func (n *NewOrderRequest) validateWireIdentifiers() error {
	if !n.hasWireIdentifiers() {
		return nil
	}

	userIdentifiers := identifiersOfType(acme.WireUser, n.Identifiers)
	deviceIdentifiers := identifiersOfType(acme.WireDevice, n.Identifiers)

	if len(userIdentifiers) != 1 {
		return fmt.Errorf("expected exactly one Wire UserID identifier; got %d", len(userIdentifiers))
	}
	if len(deviceIdentifiers) != 1 {
		return fmt.Errorf("expected exactly one Wire DeviceID identifier, got %d", len(deviceIdentifiers))
	}

	wireUserID, err := wire.ParseUserID(userIdentifiers[0].Value)
	if err != nil {
		return fmt.Errorf("failed parsing Wire UserID: %w", err)
	}

	wireDeviceID, err := wire.ParseDeviceID(deviceIdentifiers[0].Value)
	if err != nil {
		return fmt.Errorf("failed parsing Wire DeviceID: %w", err)
	}
	if _, err := wire.ParseClientID(wireDeviceID.ClientID); err != nil {
		return fmt.Errorf("invalid Wire client ID %q: %w", wireDeviceID.ClientID, err)
	}

	switch {
	case wireUserID.Domain != wireDeviceID.Domain:
		return fmt.Errorf("UserID domain %q does not match DeviceID domain %q", wireUserID.Domain, wireDeviceID.Domain)
	case wireUserID.Name != wireDeviceID.Name:
		return fmt.Errorf("UserID name %q does not match DeviceID name %q", wireUserID.Name, wireDeviceID.Name)
	case wireUserID.Handle != wireDeviceID.Handle:
		return fmt.Errorf("UserID handle %q does not match DeviceID handle %q", wireUserID.Handle, wireDeviceID.Handle)
	}

	return nil
}

// hasWireIdentifiers returns whether the [NewOrderRequest] contains
// Wire identifiers.
func (n *NewOrderRequest) hasWireIdentifiers() bool {
	for _, i := range n.Identifiers {
		if i.Type == acme.WireUser || i.Type == acme.WireDevice {
			return true
		}
	}
	return false
}

// identifiersOfType returns the Identifiers that are of type typ.
func identifiersOfType(typ acme.IdentifierType, ids []acme.Identifier) (result []acme.Identifier) {
	for _, id := range ids {
		if id.Type == typ {
			result = append(result, id)
		}
	}
	return
}

// FinalizeRequest captures the body for a Finalize order request.
type FinalizeRequest struct {
	CSR string `json:"csr"`
	csr *x509.CertificateRequest
}

// Validate validates a finalize request body.
func (f *FinalizeRequest) Validate() error {
	var err error
	// RFC 8555 isn't 100% conclusive about using raw base64-url encoding for the
	// CSR specifically, instead of "normal" base64-url encoding (incl. padding).
	// By trimming the padding from CSRs submitted by ACME clients that use
	// base64-url encoding instead of raw base64-url encoding, these are also
	// supported. This was reported in https://github.com/smallstep/certificates/issues/939
	// to be the case for a Synology DSM NAS system.
	csrBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(f.CSR, "="))
	if err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "error base64url decoding csr")
	}
	f.csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "unable to parse csr")
	}
	if err = f.csr.CheckSignature(); err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "csr failed signature check")
	}
	return nil
}

var defaultOrderExpiry = time.Hour * 24
var defaultOrderBackdate = time.Minute

// NewOrder ACME api for creating a new order.
func NewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ca := mustAuthority(ctx)
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal new-order request payload"))
		return
	}

	if err := nor.Validate(); err != nil {
		render.Error(w, r, err)
		return
	}

	// TODO(hs): gather all errors, so that we can build one response with ACME subproblems
	// include the nor.Validate() error here too, like in the example in the ACME RFC?

	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	var eak *acme.ExternalAccountKey
	if acmeProv.RequireEAB {
		if eak, err = db.GetExternalAccountKeyByAccountID(ctx, prov.GetIDForToken(), acc.ID); err != nil {
			render.Error(w, r, acme.WrapErrorISE(err, "error retrieving external account binding key"))
			return
		}
	}
	trustedPolicy := false
	if resolverCA, ok := ca.(interface {
		GetTrustedACMEPolicyResolver() provisioner.TrustedACMEPolicyResolver
	}); ok {
		if resolver := resolverCA.GetTrustedACMEPolicyResolver(); resolver != nil {
			trustedPolicy = resolver.EnabledForProvisioner(acmeProv.GetName())
		}
	}
	if trustedPolicy && !acmeProv.RequireEAB {
		logSecurityEvent(ctx, "trusted_authorization_decision",
			"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
			"identifiers", nor.Identifiers, "result", "denied", "reason", "require_eab_disabled",
		)
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType, "trusted EAB-policy authorization requires requireEAB=true on the provisioner"))
		return
	}
	if trustedPolicy && !hasNonEmptyACMEPolicy(eak) {
		logSecurityEvent(ctx, "trusted_authorization_decision",
			"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
			"identifiers", nor.Identifiers, "result", "denied", "reason", "missing_positive_account_policy",
		)
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType, "trusted EAB-policy authorization requires a bound EAB with a non-empty policy"))
		return
	}

	acmePolicy, err := newACMEPolicyEngine(eak)
	if err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error creating ACME policy engine"))
		return
	}

	for _, identifier := range nor.Identifiers {
		if trustedPolicy && identifier.Type != acme.DNS {
			logSecurityEvent(ctx, "trusted_authorization_decision",
				"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
				"identifiers", nor.Identifiers, "result", "denied", "reason", "unsupported_identifier_type",
			)
			render.Error(w, r, acme.NewError(acme.ErrorRejectedIdentifierType, "trusted EAB-policy authorization does not support identifier type %s", identifier.Type))
			return
		}
		// evaluate the ACME account level policy
		if err = isIdentifierAllowed(acmePolicy, identifier); err != nil {
			logSecurityEvent(ctx, "acme_policy_rejection",
				"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
				"identifiers", nor.Identifiers, "result", "denied", "reason", "account_policy",
			)
			if trustedPolicy {
				logSecurityEvent(ctx, "trusted_authorization_decision",
					"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
					"identifiers", nor.Identifiers, "result", "denied", "reason", "account_policy",
				)
			}
			render.Error(w, r, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
			return
		}
		// evaluate the provisioner level policy
		orderIdentifier := provisioner.ACMEIdentifier{Type: provisioner.ACMEIdentifierType(identifier.Type), Value: identifier.Value}
		if err = prov.AuthorizeOrderIdentifier(ctx, orderIdentifier); err != nil {
			logSecurityEvent(ctx, "acme_policy_rejection",
				"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
				"identifiers", nor.Identifiers, "result", "denied", "reason", "provisioner_policy",
			)
			if trustedPolicy {
				logSecurityEvent(ctx, "trusted_authorization_decision",
					"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
					"identifiers", nor.Identifiers, "result", "denied", "reason", "provisioner_policy",
				)
			}
			render.Error(w, r, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
			return
		}
	}
	// Evaluate the authority policy against the complete order. This preserves
	// the authority-wide containment boundary for multi-SAN orders rather than
	// treating each identifier as an independent request.
	if err = ca.AreSANsAllowed(ctx, identifierValues(nor.Identifiers)); err != nil {
		logSecurityEvent(ctx, "acme_policy_rejection",
			"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
			"identifiers", nor.Identifiers, "result", "denied", "reason", "authority_policy",
		)
		if trustedPolicy {
			logSecurityEvent(ctx, "trusted_authorization_decision",
				"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
				"identifiers", nor.Identifiers, "result", "denied", "reason", "authority_policy",
			)
		}
		render.Error(w, r, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
		return
	}
	trustedResult, trustedReason := "disabled", "runtime_overlay_disabled"
	if trustedPolicy {
		trustedResult, trustedReason = "allowed", "all_account_provisioner_authority_policies_passed"
	}
	logSecurityEvent(ctx, "trusted_authorization_decision",
		"account_id", acc.ID, "provisioner_id", acmeProv.GetIDForToken(),
		"identifiers", nor.Identifiers, "result", trustedResult, "reason", trustedReason,
	)

	now := clock.Now()
	// New order.
	o := &acme.Order{
		AccountID:        acc.ID,
		ProvisionerID:    prov.GetID(),
		Status:           acme.StatusPending,
		Identifiers:      nor.Identifiers,
		ExpiresAt:        now.Add(defaultOrderExpiry),
		AuthorizationIDs: make([]string, len(nor.Identifiers)),
		NotBefore:        nor.NotBefore,
		NotAfter:         nor.NotAfter,
		Trusted:          trustedPolicy,
	}

	for i, identifier := range o.Identifiers {
		az := &acme.Authorization{
			AccountID:  acc.ID,
			Identifier: identifier,
			ExpiresAt:  o.ExpiresAt,
			Status:     acme.StatusPending,
		}
		if err := newAuthorizationWithTrust(ctx, az, trustedPolicy); err != nil {
			render.Error(w, r, err)
			return
		}
		o.AuthorizationIDs[i] = az.ID
	}

	if o.NotBefore.IsZero() {
		o.NotBefore = now
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(prov.DefaultTLSCertDuration())
	}

	// if request NotBefore was empty, then backdate the order.NotBefore (now)
	// to avoid timing issues.
	if nor.NotBefore.IsZero() {
		backdate := defaultOrderBackdate
		if bd := ca.GetBackdate(); bd != nil {
			backdate = *bd
		}
		o.NotBefore = o.NotBefore.Add(-backdate)
	}

	if err := db.CreateOrder(ctx, o); err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error creating order"))
		return
	}
	logSecurityEvent(ctx, "downstream_order_created",
		"local_order_id", o.ID,
		"account_id", acc.ID,
		"provisioner_id", acmeProv.GetIDForToken(),
		"identifiers", o.Identifiers,
		"result", "success",
	)

	linker.LinkOrder(ctx, o)

	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	render.JSONStatus(w, r, o, http.StatusCreated)
}

func isIdentifierAllowed(acmePolicy policy.X509Policy, identifier acme.Identifier) error {
	if acmePolicy == nil {
		return nil
	}
	return acmePolicy.AreSANsAllowed([]string{identifier.Value})
}

func identifierValues(identifiers []acme.Identifier) []string {
	values := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		values = append(values, identifier.Value)
	}
	return values
}

func newACMEPolicyEngine(eak *acme.ExternalAccountKey) (policy.X509Policy, error) {
	if eak == nil {
		//nolint:nilnil,nolintlint // expected values
		return nil, nil
	}
	return policy.NewX509PolicyEngine(eak.Policy)
}

func hasNonEmptyACMEPolicy(eak *acme.ExternalAccountKey) bool {
	if eak == nil || eak.Policy == nil {
		return false
	}
	x509Policy := eak.Policy.X509
	// Trusted authorization substitutes for downstream DCV. It therefore needs
	// an explicit positive DNS allow-list; deny-only, wildcard-only, and
	// IP-only policies must not expand the trust boundary.
	return len(x509Policy.Allowed.DNSNames) > 0
}

func trimIfWildcard(value string) (string, bool) {
	if strings.HasPrefix(value, "*.") {
		return strings.TrimPrefix(value, "*."), true
	}
	return value, false
}

func newAuthorization(ctx context.Context, az *acme.Authorization) error {
	return newAuthorizationWithTrust(ctx, az, false)
}

func newAuthorizationWithTrust(ctx context.Context, az *acme.Authorization, trusted bool) error {
	db := acme.MustDatabaseFromContext(ctx)
	value, isWildcard := trimIfWildcard(az.Identifier.Value)
	az.Wildcard = isWildcard
	az.Identifier = acme.Identifier{
		Value: value,
		Type:  az.Identifier.Type,
	}

	chTypes := challengeTypes(az)

	var err error
	if trusted {
		prov := acme.MustProvisionerFromContext(ctx)
		az.Token, err = randutil.Alphanumeric(32)
		if err != nil {
			return acme.WrapErrorISE(err, "error generating random alphanumeric ID")
		}

		var trustedType acme.ChallengeType
		// Preserve client compatibility without performing downstream DCV.
		// RouterOS expects http-01 for ordinary DNS names, while wildcard DNS
		// identifiers can only use dns-01. Prefer that shape for trusted authz.
		if az.Identifier.Type == acme.DNS && !az.Wildcard &&
			prov.IsChallengeEnabled(ctx, provisioner.ACMEChallenge(acme.HTTP01)) {
			trustedType = acme.HTTP01
		} else {
			for _, typ := range chTypes {
				if prov.IsChallengeEnabled(ctx, provisioner.ACMEChallenge(typ)) {
					trustedType = typ
					break
				}
			}
		}
		if trustedType == "" {
			return acme.NewError(acme.ErrorServerInternalType, "trusted authorization has no enabled challenge type")
		}

		ch := &acme.Challenge{
			AccountID:   az.AccountID,
			Value:       az.Identifier.Value,
			Type:        trustedType,
			Token:       az.Token,
			Status:      acme.StatusPending,
			ValidatedAt: clock.Now().Format(time.RFC3339),
		}
		if err := db.CreateChallenge(ctx, ch); err != nil {
			return acme.WrapErrorISE(err, "error creating trusted authorization challenge")
		}
		ch.Status = acme.StatusValid
		if err := db.UpdateChallenge(ctx, ch); err != nil {
			return acme.WrapErrorISE(err, "error validating trusted authorization challenge")
		}
		az.Challenges = []*acme.Challenge{ch}
		az.Status = acme.StatusValid
		return db.CreateAuthorization(ctx, az)
	}

	az.Token, err = randutil.Alphanumeric(32)
	if err != nil {
		return acme.WrapErrorISE(err, "error generating random alphanumeric ID")
	}

	prov := acme.MustProvisionerFromContext(ctx)
	az.Challenges = make([]*acme.Challenge, 0, len(chTypes))
	for _, typ := range chTypes {
		if !prov.IsChallengeEnabled(ctx, provisioner.ACMEChallenge(typ)) {
			continue
		}

		var target string
		switch az.Identifier.Type {
		case acme.WireUser:
			wireOptions, err := prov.GetOptions().GetWireOptions()
			if err != nil {
				return acme.WrapErrorISE(err, "failed getting Wire options")
			}
			target, err = wireOptions.GetOIDCOptions().EvaluateTarget("") // TODO(hs): determine if required by Wire
			if err != nil {
				return acme.WrapError(acme.ErrorMalformedType, err, "invalid Go template registered for 'target'")
			}
		case acme.WireDevice:
			wireID, err := wire.ParseDeviceID(az.Identifier.Value)
			if err != nil {
				return acme.WrapError(acme.ErrorMalformedType, err, "failed parsing WireDevice")
			}
			clientID, err := wire.ParseClientID(wireID.ClientID)
			if err != nil {
				return acme.WrapError(acme.ErrorMalformedType, err, "failed parsing ClientID")
			}
			wireOptions, err := prov.GetOptions().GetWireOptions()
			if err != nil {
				return acme.WrapErrorISE(err, "failed getting Wire options")
			}
			target, err = wireOptions.GetDPOPOptions().EvaluateTarget(clientID.DeviceID)
			if err != nil {
				return acme.WrapError(acme.ErrorMalformedType, err, "invalid Go template registered for 'target'")
			}
		}

		ch := &acme.Challenge{
			AccountID: az.AccountID,
			Value:     az.Identifier.Value,
			Type:      typ,
			Token:     az.Token,
			Status:    acme.StatusPending,
			Target:    target,
		}
		if err := db.CreateChallenge(ctx, ch); err != nil {
			return acme.WrapErrorISE(err, "error creating challenge")
		}
		az.Challenges = append(az.Challenges, ch)
	}
	if err = db.CreateAuthorization(ctx, az); err != nil {
		return acme.WrapErrorISE(err, "error creating authorization")
	}
	return nil
}

// GetOrder ACME api for retrieving an order.
func GetOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	o, err := db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}
	if o.Status == acme.StatusProcessing {
		ca := mustAuthority(ctx)
		if err := validateCurrentOrderPolicy(ctx, o, db, ca, prov); err != nil {
			o.Status = acme.StatusInvalid
			o.Error = acme.NewError(acme.ErrorUnauthorizedType, "current policy rejected processing order")
			o.CSR = nil
			o.Trusted = false
			if updateErr := db.UpdateOrder(ctx, o); updateErr != nil {
				render.Error(w, r, acme.WrapErrorISE(updateErr, "error updating policy-rejected order"))
				return
			}
		} else if len(o.CSR) == 0 {
			o.Status = acme.StatusInvalid
			o.Error = acme.NewError(acme.ErrorServerInternalType, "processing order cannot be recovered: CSR is unavailable")
			o.Trusted = false
			if err := db.UpdateOrder(ctx, o); err != nil {
				render.Error(w, r, acme.WrapErrorISE(err, "error updating unrecoverable order"))
				return
			}
		} else if csr, parseErr := x509.ParseCertificateRequest(o.CSR); parseErr != nil {
			o.Status = acme.StatusInvalid
			o.Error = acme.NewError(acme.ErrorServerInternalType, "processing order cannot be recovered: invalid CSR")
			o.CSR = nil
			o.Trusted = false
			if err := db.UpdateOrder(ctx, o); err != nil {
				render.Error(w, r, acme.WrapErrorISE(err, "error updating unrecoverable order"))
				return
			}
		} else {
			startAsyncFinalization(ctx, db, o.ID, csr, ca, prov)
		}
	}
	if err = o.UpdateStatus(ctx, db); err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error updating order status"))
		return
	}

	linker.LinkOrder(ctx, o)

	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	render.JSON(w, r, o)
}

// FinalizeOrder attempts to finalize an order and create a certificate.
func FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	var fr FinalizeRequest
	if err := json.Unmarshal(payload.value, &fr); err != nil {
		render.Error(w, r, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal finalize-order request payload"))
		return
	}
	if err := fr.Validate(); err != nil {
		render.Error(w, r, err)
		return
	}

	o, err := db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		render.Error(w, r, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}

	ca := mustAuthority(ctx)

	// Validate the order is ready without signing yet.
	if err = o.UpdateStatus(ctx, db); err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error updating order status"))
		return
	}
	if o.Status != acme.StatusReady {
		render.Error(w, r, acme.NewError(acme.ErrorOrderNotReadyType, "order %s is not ready", o.ID))
		return
	}
	if err = validateCurrentOrderPolicy(ctx, o, db, ca, prov); err != nil {
		render.Error(w, r, err)
		return
	}

	// Immediately mark as processing and return — RFC 8555 §7.4 async finalization.
	// This prevents ACME clients with short read timeouts (e.g. certbot's hardcoded
	// 45s DEFAULT_NETWORK_TIMEOUT) from timing out while a slow external CA signs.
	o.CSR = append([]byte(nil), fr.csr.Raw...)
	o.Status = acme.StatusProcessing
	if err = db.UpdateOrder(ctx, o); err != nil {
		render.Error(w, r, acme.WrapErrorISE(err, "error setting order to processing"))
		return
	}
	linker.LinkOrder(ctx, o)
	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	w.Header().Set("Retry-After", "15")
	render.JSON(w, r, o)

	// Sign the certificate in the background. DB status drives client polling responses.
	// We capture orderID and csr rather than the order pointer to avoid data races with
	// the HTTP response still being flushed.
	orderID, csr := o.ID, fr.csr
	startAsyncFinalization(ctx, db, orderID, csr, ca, prov)
}

var asyncFinalizations sync.Map

func startAsyncFinalization(ctx context.Context, db acme.DB, orderID string, csr *x509.CertificateRequest, ca acme.CertificateAuthority, prov acme.Provisioner) {
	if !claimAsyncFinalization(orderID) {
		return
	}
	go func() {
		defer asyncFinalizations.Delete(orderID)
		bgCtx := context.WithoutCancel(ctx)
		bgOrder, err := db.GetOrder(bgCtx, orderID)
		if err != nil {
			slog.Error("async finalization: failed to re-fetch order", "order", orderID, "err", err)
			return
		}
		bgOrder.Status = acme.StatusReady
		if err := validateCurrentOrderPolicy(bgCtx, bgOrder, db, ca, prov); err != nil {
			slog.Error("async finalization rejected by current policy", "order", orderID, "err", err)
			logSecurityEvent(bgCtx, "finalization_failed",
				"local_order_id", orderID, "account_id", bgOrder.AccountID,
				"provisioner_id", prov.GetIDForToken(), "csr_sha256", csrSHA256(csr.Raw),
				"identifiers", bgOrder.Identifiers, "result", "failure", "reason", "current_policy_rejected",
			)
			bgOrder.Status = acme.StatusInvalid
			bgOrder.Error = acme.NewError(acme.ErrorUnauthorizedType, "current policy rejected order")
			bgOrder.CSR = nil
			bgOrder.Trusted = false
			if updateErr := db.UpdateOrder(bgCtx, bgOrder); updateErr != nil {
				slog.Error("async finalization: failed to persist policy failure", "order", orderID, "err", updateErr)
			} else {
				notifyOrderFinalized(ca, orderID)
			}
			return
		}
		if err := bgOrder.Finalize(bgCtx, db, csr, ca, prov); err != nil {
			slog.Error("async finalization failed", "order", orderID, "err", err)
			logSecurityEvent(bgCtx, "finalization_failed",
				"local_order_id", orderID, "account_id", bgOrder.AccountID,
				"provisioner_id", prov.GetIDForToken(), "csr_sha256", csrSHA256(csr.Raw),
				"identifiers", bgOrder.Identifiers, "result", "failure", "reason", "issuer_finalization_failed",
			)
			bgOrder.Status = acme.StatusInvalid
			bgOrder.Error = acme.NewError(acme.ErrorServerInternalType, "certificate finalization failed")
			bgOrder.CSR = nil
			bgOrder.Trusted = false
			if updateErr := db.UpdateOrder(bgCtx, bgOrder); updateErr != nil {
				slog.Error("async finalization: failed to persist failure", "order", orderID, "err", updateErr)
			} else {
				notifyOrderFinalized(ca, orderID)
			}
			return
		}
		logSecurityEvent(bgCtx, "finalization_succeeded",
			"local_order_id", orderID, "account_id", bgOrder.AccountID,
			"provisioner_id", prov.GetIDForToken(), "csr_sha256", csrSHA256(csr.Raw),
			"identifiers", bgOrder.Identifiers, "result", "success",
		)
		notifyOrderFinalized(ca, orderID)
		slog.Info("async finalization succeeded", "order", orderID)
	}()
}

func claimAsyncFinalization(orderID string) bool {
	_, loaded := asyncFinalizations.LoadOrStore(orderID, struct{}{})
	return !loaded
}

type acmeOrderFinalizationObserver interface {
	ACMEOrderFinalized(requestID string) error
}

// notifyOrderFinalized runs only after the order's terminal state has been
// durably written. Failure to remove recovery metadata is safe: stale entries
// are preferable to losing a mapping before the local commit.
func notifyOrderFinalized(ca acme.CertificateAuthority, requestID string) {
	observer, ok := ca.(acmeOrderFinalizationObserver)
	if !ok {
		return
	}
	if err := observer.ACMEOrderFinalized(requestID); err != nil {
		slog.Error("async finalization: failed to clean recovery metadata", "order", requestID, "err", err)
	}
}

func validateCurrentOrderPolicy(ctx context.Context, o *acme.Order, db acme.DB, ca acme.CertificateAuthority, prov acme.Provisioner) error {
	reject := func(reason string, err error) error {
		fields := []any{
			"local_order_id", o.ID, "account_id", o.AccountID,
			"provisioner_id", prov.GetIDForToken(), "identifiers", o.Identifiers,
			"result", "denied", "reason", reason,
		}
		if len(o.CSR) > 0 {
			fields = append(fields, "csr_sha256", csrSHA256(o.CSR))
		}
		logSecurityEvent(ctx, "acme_policy_rejection", fields...)
		if o.Trusted {
			logSecurityEvent(ctx, "trusted_authorization_decision", fields...)
		}
		return err
	}
	if err := ca.AreSANsAllowed(ctx, identifierValues(o.Identifiers)); err != nil {
		return reject("authority_policy", acme.WrapError(acme.ErrorRejectedIdentifierType, err, "current authority policy rejected order"))
	}
	for _, identifier := range o.Identifiers {
		if err := prov.AuthorizeOrderIdentifier(ctx, provisioner.ACMEIdentifier{Type: provisioner.ACMEIdentifierType(identifier.Type), Value: identifier.Value}); err != nil {
			return reject("provisioner_policy", acme.WrapError(acme.ErrorRejectedIdentifierType, err, "current provisioner policy rejected order"))
		}
	}

	if !o.Trusted {
		return nil
	}

	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		return reject("acme_provisioner_missing", err)
	}
	resolverCA, ok := ca.(interface {
		GetTrustedACMEPolicyResolver() provisioner.TrustedACMEPolicyResolver
	})
	if !ok || resolverCA.GetTrustedACMEPolicyResolver() == nil || !resolverCA.GetTrustedACMEPolicyResolver().EnabledForProvisioner(acmeProv.GetName()) {
		return reject("trusted_overlay_disabled", acme.NewError(acme.ErrorUnauthorizedType, "trusted authorization is no longer enabled"))
	}
	eak, err := db.GetExternalAccountKeyByAccountID(ctx, prov.GetIDForToken(), o.AccountID)
	if err != nil {
		return reject("eab_binding_unavailable", acme.WrapError(acme.ErrorUnauthorizedType, err, "trusted authorization EAB binding is unavailable"))
	}
	if !hasNonEmptyACMEPolicy(eak) {
		return reject("account_policy_missing_or_empty", acme.NewError(acme.ErrorUnauthorizedType, "trusted authorization policy is empty"))
	}
	for _, identifier := range o.Identifiers {
		if identifier.Type != acme.DNS {
			return reject("unsupported_identifier_type", acme.NewError(acme.ErrorRejectedIdentifierType, "trusted authorization does not support identifier type %s", identifier.Type))
		}
		if err := isIdentifierAllowedMust(eak, identifier); err != nil {
			return reject("account_policy", acme.WrapError(acme.ErrorRejectedIdentifierType, err, "current account policy rejected order"))
		}
	}
	fields := []any{
		"local_order_id", o.ID, "account_id", o.AccountID,
		"provisioner_id", prov.GetIDForToken(), "identifiers", o.Identifiers,
		"result", "allowed", "reason", "current_policy_recheck_passed",
	}
	if len(o.CSR) > 0 {
		fields = append(fields, "csr_sha256", csrSHA256(o.CSR))
	}
	logSecurityEvent(ctx, "trusted_authorization_decision", fields...)
	return nil
}

func isIdentifierAllowedMust(eak *acme.ExternalAccountKey, identifier acme.Identifier) error {
	engine, err := newACMEPolicyEngine(eak)
	if err != nil {
		return err
	}
	return isIdentifierAllowed(engine, identifier)
}

// challengeTypes determines the types of challenges that should be used
// for the ACME authorization request.
func challengeTypes(az *acme.Authorization) []acme.ChallengeType {
	var chTypes []acme.ChallengeType

	switch az.Identifier.Type {
	case acme.IP:
		chTypes = []acme.ChallengeType{acme.HTTP01, acme.TLSALPN01}
	case acme.DNS:
		chTypes = []acme.ChallengeType{acme.DNS01}
		// HTTP and TLS challenges can only be used for identifiers without wildcards.
		if !az.Wildcard {
			chTypes = append(chTypes, []acme.ChallengeType{acme.HTTP01, acme.TLSALPN01}...)
		}
	case acme.PermanentIdentifier:
		chTypes = []acme.ChallengeType{acme.DEVICEATTEST01}
	case acme.WireUser:
		chTypes = []acme.ChallengeType{acme.WIREOIDC01}
	case acme.WireDevice:
		chTypes = []acme.ChallengeType{acme.WIREDPOP01}
	default:
		chTypes = []acme.ChallengeType{}
	}

	return chTypes
}
