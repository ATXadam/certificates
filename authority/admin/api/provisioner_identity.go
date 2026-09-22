package api

import (
	"context"
	"fmt"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/acme"
)

// acmeProvisionerID returns the identifier used by the ACME runtime for EAB
// and account-policy storage. The linkedca provisioner in an admin request is
// an administrative record and its ID is not necessarily the runtime ID.
func acmeProvisionerID(ctx context.Context) (string, error) {
	if p, ok := acme.ProvisionerFromContext(ctx); ok {
		if id := p.GetIDForToken(); id != "" {
			return id, nil
		}
		return "", fmt.Errorf("ACME provisioner %q has an empty protocol ID", p.GetName())
	}
	if p, ok := linkedca.ProvisionerFromContext(ctx); ok {
		if p.GetDetails().GetACME() != nil && p.GetName() != "" {
			return "acme/" + p.GetName(), nil
		}
		return "", fmt.Errorf("provisioner %q is not an ACME provisioner", p.GetName())
	}
	return "", fmt.Errorf("ACME runtime provisioner is missing from request context")
}
