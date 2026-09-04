// Which plan tiers this run can observe, and the secret each one needs.
//
// A tier is observable only when its secret holds something non-empty. Actions
// interpolates a secret that does not exist to an EMPTY STRING rather than
// leaving the variable unset, and a client built with an empty key sends no
// authorization header at all, so an empty key runs as a second unauthenticated
// client and every comparison against it is vacuously true.

package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Ascending, one rung per plan tier. widens is what the rung promises against
// whichever observable rung sits below it: a paid tier serves strictly more than
// the tier under it, while a free key and no key at all are the same entitlement
// reached two ways.
//
// Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
// turns a pricing change into a red SDK build; the relation between the tiers is
// what the client actually has to keep.
var rungs = []rung{
	{tier: "unauth", secret: "", widens: false},
	{tier: "free", secret: "VPNDETECTION_STAGING_KEY_FREE", widens: false},
	{tier: "starter", secret: "VPNDETECTION_STAGING_KEY_STARTER", widens: true},
	{tier: "scale", secret: "VPNDETECTION_STAGING_KEY_SCALE", widens: true},
	{tier: "max", secret: "VPNDETECTION_STAGING_KEY_MAX", widens: true},
}

type rung struct {
	tier   string
	secret string
	widens bool
}

func TestMain(m *testing.M) {
	var absent []string
	var present []string
	for _, r := range rungs {
		if r.skipReason() == "" {
			present = append(present, r.tier)
			continue
		}
		absent = append(absent, r.tier)
	}
	fmt.Printf("==> tiers with a key: %s\n", strings.Join(present, ", "))
	if len(absent) > 0 {
		notice(fmt.Sprintf("no staging key for %s: those tiers are skipped",
			strings.Join(absent, ", ")))
	}
	code := m.Run()
	removeTempDir()
	os.Exit(code)
}

func (r rung) key() string {
	if r.secret == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(r.secret))
}

// A reason, or the empty string when this tier can be exercised.
func (r rung) skipReason() string {
	if r.secret == "" || r.key() != "" {
		return ""
	}
	return fmt.Sprintf("%s is not set, so the %s tier cannot be exercised", r.secret, r.tier)
}

func unauthRung() rung {
	return rungs[0]
}

func maxRung() rung {
	return rungs[len(rungs)-1]
}

func observableRungs() []rung {
	var open []rung
	for _, r := range rungs {
		if r.skipReason() == "" {
			open = append(open, r)
		}
	}
	return open
}

// The ladder needs two rungs to say anything. The unauthenticated one is always
// there, so this only fires when no tier secret at all is configured.
func ladderSkip() string {
	if len(observableRungs()) > 1 {
		return ""
	}
	return "no tier secret is set, so there is no ladder to compare"
}

// Surfaced on the workflow run itself, so a skip is visible without opening the
// log and reading to the end of it.
func notice(message string) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Printf("::notice title=Integration::%s\n", message)
		return
	}
	fmt.Printf("==> %s\n", message)
}
