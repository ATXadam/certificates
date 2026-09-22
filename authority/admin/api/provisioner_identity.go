package api

import (
	"context"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/acme"
)

// acmeProvisionerID returns the identifier used by the ACME runtime for EAB
// and account-policy storage. The linkedca provisioner in an admin request is
// an administrative record and its ID is not necessarily the runtime ID.
func acmeProvisionerID(ctx context.Context) string {
	if p, ok := acme.ProvisionerFromContext(ctx); ok {
		return p.GetID()
	}
	return linkedca.MustProvisionerFromContext(ctx).GetId()
}
