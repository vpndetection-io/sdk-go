package vpndetection

import (
	"context"
	"net/http"

	"github.com/vpndetection-io/sdk-go/v3/internal/api"
)

// The account shapes, re-exported so a consumer never has to name an internal
// package.
type (
	// Account is what a key is entitled to and what it has spent.
	Account = api.AccountMe
	// AccountApikey is the credential itself. The key is never echoed back -
	// only its id, which is what the console shows.
	AccountApikey = api.AccountApikey
	// AccountPlan is the plan behind the key, and the field tier that decides
	// how much of a lookup answer comes back.
	AccountPlan = api.AccountPlan
	// AccountUsage is consumption against the allowance.
	AccountUsage = api.AccountUsage
)

// Me reports what this client's key is entitled to and how much of it has been
// used.
//
// Unlike a lookup there is no useful unauthenticated answer, so a client built
// without a key gets an unauthorized error rather than a partial one.
//
// Usage is counted against the ALLOWANCE WINDOW - the anniversary of the
// subscription, not the calendar month and not the billing period - and the
// number is the same one a lookup is gated on. It can lag by a few seconds,
// because requests are counted in memory and flushed in aggregate.
//
// Deliberately NOT cached: the whole point is what has been spent, and a
// cached answer is a wrong one within seconds of the next request.
func (c *Client) Me(ctx context.Context, opts ...LookupOption) (*Account, error) {
	call := c.callConfig()
	for _, opt := range opts {
		opt.applyLookup(&call)
	}
	return withRetry(ctx, call.retries, func() (*Account, error) {
		res, err := c.api.AccountMeWithResponse(ctx)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200, nil
	})
}
