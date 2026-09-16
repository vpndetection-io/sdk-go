// The published module's OAuth surface against staging, on a keyless client.
// Nothing polls, since nobody approves the sign-in; one device authorization a run.

package integration

import (
	"errors"
	"slices"
	"strings"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go/v5"
)

// The only client the server registers, already public in the CLI's source.
const oauthClientID = "vpndetection-cli"

func TestOauthMetadataNamesStagingAsTheIssuer(t *testing.T) {
	client, _ := clientFor(t, unauthRung())

	metadata, err := client.Oauth.Metadata(t.Context())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if metadata.Issuer != staging {
		t.Errorf("issuer is %q, want %q", metadata.Issuer, staging)
	}
	if metadata.DeviceAuthorizationEndpoint == nil {
		t.Error("device_authorization_endpoint is absent")
	}
	if methods := metadata.CodeChallengeMethodsSupported; methods == nil || !slices.Contains(*methods, "S256") {
		t.Errorf("code_challenge_methods_supported is %v, want it to hold S256", methods)
	}
}

func TestOauthRevokeAcceptsAnyToken(t *testing.T) {
	client, _ := clientFor(t, unauthRung())

	if err := client.Oauth.Revoke(t.Context(), oauthClientID, "mo_rt_sdk-ci-not-a-token"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestOauthAnUnknownDeviceCodeHasExpired(t *testing.T) {
	client, _ := clientFor(t, unauthRung())

	_, err := client.Oauth.ExchangeDeviceCode(t.Context(), oauthClientID, "mo_dc_sdk-ci-not-a-code")
	var refused *vpndetection.OauthError
	expired := errors.Is(err, vpndetection.ErrOauthExpiredToken) && errors.As(err, &refused)
	if !expired || refused.StatusCode != 400 {
		t.Fatalf("error was %v, want an expired token answered with status 400", err)
	}
}

// slow_down passes: the server allows 30 a minute per source address, shared
// by everything building on this box or runner.
func TestOauthDeviceAuthorizationStartsASignIn(t *testing.T) {
	client, _ := clientFor(t, unauthRung())

	device, err := client.Oauth.DeviceAuthorization(t.Context(), oauthClientID,
		vpndetection.DeviceAuthorizationOptions{Scope: "account.read"})
	var refused *vpndetection.OauthError
	if errors.As(err, &refused) && refused.ErrorCode == "slow_down" {
		t.Logf("refused with slow_down, which passes: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("DeviceAuthorization: %v", err)
	}
	if device.DeviceCode == "" || device.UserCode == "" {
		t.Errorf("device_code %q or user_code %q is empty", device.DeviceCode, device.UserCode)
	}
	if !strings.HasSuffix(device.VerificationURI, "/device") {
		t.Errorf("verification_uri is %q, want it to end /device", device.VerificationURI)
	}
	if device.ExpiresIn <= 0 || device.Interval <= 0 {
		t.Errorf("expires_in %d and interval %d, want both positive", device.ExpiresIn, device.Interval)
	}
}
