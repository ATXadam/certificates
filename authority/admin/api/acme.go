package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
)

// CreateExternalAccountKeyRequest is the type for POST /admin/acme/eab requests
type CreateExternalAccountKeyRequest struct {
	Reference string `json:"reference"`
}

// Validate validates a new ACME EAB Key request body.
func (r *CreateExternalAccountKeyRequest) Validate() error {
	if len(r.Reference) > 256 { // an arbitrary, but sensible (IMO), limit
		return fmt.Errorf("reference length %d exceeds the maximum (256)", len(r.Reference))
	}
	return nil
}

// GetExternalAccountKeysResponse is the type for GET /admin/acme/eab responses
type GetExternalAccountKeysResponse struct {
	EAKs       []*linkedca.EABKey `json:"eaks"`
	NextCursor string             `json:"nextCursor"`
}

// requireEABEnabled is a middleware that ensures ACME EAB is enabled
// before serving requests that act on ACME EAB credentials.
func requireEABEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		prov := linkedca.MustProvisionerFromContext(ctx)

		acmeProvisioner := prov.GetDetails().GetACME()
		if acmeProvisioner == nil {
			render.Error(w, r, admin.NewErrorISE("error getting ACME details for provisioner '%s'", prov.GetName()))
			return
		}

		if !acmeProvisioner.RequireEab {
			render.Error(w, r, admin.NewError(admin.ErrorBadRequestType, "ACME EAB not enabled for provisioner '%s'", prov.GetName()))
			return
		}

		next(w, r)
	}
}

// ACMEAdminResponder is responsible for writing ACME admin responses
type ACMEAdminResponder interface {
	GetExternalAccountKeys(w http.ResponseWriter, r *http.Request)
	CreateExternalAccountKey(w http.ResponseWriter, r *http.Request)
	DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request)
}

// acmeAdminResponder implements ACMEAdminResponder.
type acmeAdminResponder struct{}

func acmeProvisionerFromContext(ctx context.Context) (*linkedca.Provisioner, error) {
	prov, ok := linkedca.ProvisionerFromContext(ctx)
	if !ok {
		return nil, admin.NewErrorISE("ACME provisioner is not in the request context")
	}
	return prov, nil
}

func acmeDatabaseFromContext(ctx context.Context) (acme.DB, error) {
	db, ok := acme.DatabaseFromContext(ctx)
	if !ok {
		return nil, admin.NewErrorISE("ACME database is not in the request context")
	}
	return db, nil
}

// NewACMEAdminResponder returns a new ACMEAdminResponder
func NewACMEAdminResponder() ACMEAdminResponder {
	return &acmeAdminResponder{}
}

// GetExternalAccountKeys writes the response for the EAB keys GET endpoint
func (h *acmeAdminResponder) GetExternalAccountKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, err := acmeProvisionerFromContext(ctx); err != nil {
		render.Error(w, r, err)
		return
	}
	provisionerID, err := acmeProvisionerID(ctx)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error resolving ACME protocol provisioner ID"))
		return
	}
	db, err := acmeDatabaseFromContext(ctx)
	if err != nil {
		render.Error(w, r, err)
		return
	}
	if reference := chi.URLParam(r, "reference"); reference != "" {
		key, err := db.GetExternalAccountKeyByReference(ctx, provisionerID, reference)
		if err != nil {
			render.Error(w, r, admin.WrapErrorISE(err, "error retrieving ACME EAB key"))
			return
		}
		if key == nil {
			render.Error(w, r, admin.NewError(admin.ErrorNotFoundType, "ACME EAB key does not exist"))
			return
		}
		render.JSON(w, r, eakToLinked(key))
		return
	}
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "error parsing cursor and limit"))
		return
	}
	keys, next, err := db.GetExternalAccountKeys(ctx, provisionerID, cursor, limit)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error retrieving ACME EAB keys"))
		return
	}
	response := &GetExternalAccountKeysResponse{NextCursor: next}
	for _, key := range keys {
		response.EAKs = append(response.EAKs, eakToLinked(key))
	}
	render.JSON(w, r, response)
}

// CreateExternalAccountKey writes the response for the EAB key POST endpoint
func (h *acmeAdminResponder) CreateExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	var req CreateExternalAccountKeyRequest
	if err := read.JSON(r.Body, &req); err != nil {
		render.Error(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.Error(w, r, admin.WrapError(admin.ErrorBadRequestType, err, "invalid ACME EAB key request"))
		return
	}
	if _, err := acmeProvisionerFromContext(r.Context()); err != nil {
		render.Error(w, r, err)
		return
	}
	provisionerID, err := acmeProvisionerID(r.Context())
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error resolving ACME protocol provisioner ID"))
		return
	}
	db, err := acmeDatabaseFromContext(r.Context())
	if err != nil {
		render.Error(w, r, err)
		return
	}
	key, err := db.CreateExternalAccountKey(r.Context(), provisionerID, req.Reference)
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error creating ACME EAB key"))
		return
	}
	render.JSONStatus(w, r, eakToLinked(key), http.StatusCreated)
}

// DeleteExternalAccountKey writes the response for the EAB key DELETE endpoint
func (h *acmeAdminResponder) DeleteExternalAccountKey(w http.ResponseWriter, r *http.Request) {
	if _, err := acmeProvisionerFromContext(r.Context()); err != nil {
		render.Error(w, r, err)
		return
	}
	provisionerID, err := acmeProvisionerID(r.Context())
	if err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error resolving ACME protocol provisioner ID"))
		return
	}
	db, err := acmeDatabaseFromContext(r.Context())
	if err != nil {
		render.Error(w, r, err)
		return
	}
	if err := db.DeleteExternalAccountKey(r.Context(), provisionerID, chi.URLParam(r, "id")); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error deleting ACME EAB key"))
		return
	}
	render.JSON(w, r, map[string]string{"status": "ok"})
}

func eakToLinked(k *acme.ExternalAccountKey) *linkedca.EABKey {
	if k == nil {
		return nil
	}

	eak := &linkedca.EABKey{
		Id:          k.ID,
		HmacKey:     k.HmacKey,
		Provisioner: k.ProvisionerID,
		Reference:   k.Reference,
		Account:     k.AccountID,
		CreatedAt:   timestamppb.New(k.CreatedAt),
		BoundAt:     timestamppb.New(k.BoundAt),
	}

	if k.Policy != nil {
		eak.Policy = &linkedca.Policy{
			X509: &linkedca.X509Policy{
				Allow: &linkedca.X509Names{},
				Deny:  &linkedca.X509Names{},
			},
		}
		eak.Policy.X509.Allow.Dns = k.Policy.X509.Allowed.DNSNames
		eak.Policy.X509.Allow.Ips = k.Policy.X509.Allowed.IPRanges
		eak.Policy.X509.Deny.Dns = k.Policy.X509.Denied.DNSNames
		eak.Policy.X509.Deny.Ips = k.Policy.X509.Denied.IPRanges
		eak.Policy.X509.AllowWildcardNames = k.Policy.X509.AllowWildcardNames
	}

	return eak
}

func linkedEAKToCertificates(k *linkedca.EABKey) *acme.ExternalAccountKey {
	if k == nil {
		return nil
	}

	eak := &acme.ExternalAccountKey{
		ID:            k.Id,
		ProvisionerID: k.Provisioner,
		Reference:     k.Reference,
		AccountID:     k.Account,
		HmacKey:       k.HmacKey,
		CreatedAt:     k.CreatedAt.AsTime(),
		BoundAt:       k.BoundAt.AsTime(),
	}

	if policy := k.GetPolicy(); policy != nil {
		eak.Policy = &acme.Policy{}
		if x509 := policy.GetX509(); x509 != nil {
			eak.Policy.X509 = acme.X509Policy{}
			if allow := x509.GetAllow(); allow != nil {
				eak.Policy.X509.Allowed = acme.PolicyNames{}
				eak.Policy.X509.Allowed.DNSNames = allow.Dns
				eak.Policy.X509.Allowed.IPRanges = allow.Ips
			}
			if deny := x509.GetDeny(); deny != nil {
				eak.Policy.X509.Denied = acme.PolicyNames{}
				eak.Policy.X509.Denied.DNSNames = deny.Dns
				eak.Policy.X509.Denied.IPRanges = deny.Ips
			}
			eak.Policy.X509.AllowWildcardNames = x509.AllowWildcardNames
		}
	}

	return eak
}
