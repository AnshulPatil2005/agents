/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// discoveryServer serves one body at the discovery path over TLS and returns
// its URL alongside a client that trusts it.
func discoveryServer(t *testing.T, status int, body string) (string, *http.Client) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL, server.Client()
}

func TestDiscover(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantIssuer  string
		wantJWKSURI string
		wantErr     string
	}{
		{
			name:        "a well-formed document resolves",
			status:      http.StatusOK,
			body:        `{"issuer":"https://keycloak.example.com/realms/agents","jwks_uri":"https://keycloak.example.com/realms/agents/protocol/openid-connect/certs"}`,
			wantIssuer:  "https://keycloak.example.com/realms/agents",
			wantJWKSURI: "https://keycloak.example.com/realms/agents/protocol/openid-connect/certs",
		},
		{
			name:   "extra fields are ignored",
			status: http.StatusOK,
			body: `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys",` +
				`"authorization_endpoint":"https://issuer.example/auth","id_token_signing_alg_values_supported":["RS256"]}`,
			wantIssuer:  "https://issuer.example",
			wantJWKSURI: "https://issuer.example/keys",
		},
		{
			// An issuer that advertises nothing cannot be matched against an iss
			// claim, so recording it would look resolved and verify nothing.
			name:    "an empty issuer is rejected",
			status:  http.StatusOK,
			body:    `{"issuer":"","jwks_uri":"https://issuer.example/keys"}`,
			wantErr: "empty issuer",
		},
		{
			name:    "a missing issuer is rejected",
			status:  http.StatusOK,
			body:    `{"jwks_uri":"https://issuer.example/keys"}`,
			wantErr: "empty issuer",
		},
		{
			// Fetching keys over plaintext would let anyone on the path swap them.
			name:    "a plaintext jwks_uri is rejected",
			status:  http.StatusOK,
			body:    `{"issuer":"https://issuer.example","jwks_uri":"http://issuer.example/keys"}`,
			wantErr: "invalid jwks_uri",
		},
		{
			name:    "a missing jwks_uri is rejected",
			status:  http.StatusOK,
			body:    `{"issuer":"https://issuer.example"}`,
			wantErr: "invalid jwks_uri",
		},
		{
			name:    "a non-200 response is rejected",
			status:  http.StatusNotFound,
			body:    `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys"}`,
			wantErr: "fetch discovery document",
		},
		{
			// A discovery URL is operator-supplied and may point at something
			// that is not a discovery document at all, such as a login page.
			name:    "a non-JSON body is rejected",
			status:  http.StatusOK,
			body:    `<html><body>Sign in</body></html>`,
			wantErr: "fetch discovery document",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, client := discoveryServer(t, tt.status, tt.body)

			got, err := discoverWith(context.Background(), client, url, withDefaults(Options{}))

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error: got %q, want it to contain %q", err, tt.wantErr)
				}
				if got.Issuer != "" || got.JWKSURI != "" {
					t.Errorf("a rejected document must resolve nothing, got %+v", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("discoverWith: %v", err)
			}
			if got.Issuer != tt.wantIssuer {
				t.Errorf("issuer: got %q, want %q", got.Issuer, tt.wantIssuer)
			}
			if got.JWKSURI != tt.wantJWKSURI {
				t.Errorf("jwksUri: got %q, want %q", got.JWKSURI, tt.wantJWKSURI)
			}
		})
	}
}

// TestDiscoverRejectsNonHTTPSURL covers the check that happens before any
// request is made, so no server is involved.
func TestDiscoverRejectsNonHTTPSURL(t *testing.T) {
	for _, url := range []string{
		"http://keycloak.example.com/.well-known/openid-configuration",
		"ftp://keycloak.example.com/x",
		"keycloak.example.com/x",
		"",
	} {
		t.Run(fmt.Sprintf("%q", url), func(t *testing.T) {
			if _, err := Discover(context.Background(), url, Options{}); err == nil {
				t.Error("expected a non-HTTPS discovery URL to be rejected")
			}
		})
	}
}

// TestDiscoverEnforcesTheResponseSizeLimit stops a discovery URL pointing at
// something enormous from being read into memory.
func TestDiscoverEnforcesTheResponseSizeLimit(t *testing.T) {
	padding := strings.Repeat("x", 4096)
	body := fmt.Sprintf(`{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys","pad":%q}`, padding)
	url, client := discoveryServer(t, http.StatusOK, body)

	opts := withDefaults(Options{})
	opts.MaxResponseSize = 512

	if _, err := discoverWith(context.Background(), client, url, opts); err == nil {
		t.Fatal("expected an oversized document to be rejected")
	} else if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error: got %q, want it to mention the size limit", err)
	}
}

// TestDiscoverDoesNotFollowRedirects keeps a discovery URL from being bounced
// somewhere the operator did not name. Discover is used here rather than
// discoverWith so the real client's CheckRedirect is what is under test.
func TestDiscoverDoesNotFollowRedirects(t *testing.T) {
	var reached bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"issuer":"https://evil.example","jwks_uri":"https://evil.example/keys"}`))
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	// The redirect response itself is not JSON, so this fails either way; the
	// assertion that matters is that the redirect target was never contacted.
	if _, err := discoverWith(context.Background(), redirectRefusingClient(redirector),
		redirector.URL, withDefaults(Options{})); err == nil {
		t.Error("expected a redirect not to resolve")
	}
	if reached {
		t.Error("the redirect was followed to a host the operator did not name")
	}
}

// redirectRefusingClient is the test server's client with Discover's redirect
// policy applied, so the policy rather than the trust store is what is tested.
func redirectRefusingClient(server *httptest.Server) *http.Client {
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}
