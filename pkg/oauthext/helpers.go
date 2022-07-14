package oauthext

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"net"
	"net/http"
)

// SolidOIDCHelper implements the CredentialHelper interface defined in
// https://github.com/kubeflow/internal-acls/blob/master/google_groups/pkg/gcp/credentials.go#L28
type SolidOIDCHelper struct {
	config *oauth2.Config
	Log    logr.Logger
}

// NewSolidOIDCHelper creates a new instance of the helper to obtain solid OIDC credentaisl.
// clientID: This should be the URI hosting the client id document describing the application.
// oidcProviderUri: The URI of the OIDC provider
//
// This will start a server to accept the callbacks that will contain the credentials.
func NewSolidOIDCHelper(clientID string, oidcProviderUri string, log logr.Logger) (*SolidOIDCHelper, error) {
	// Fetch the client id document and use that to get the callback URI
	doc, err := fetchClientIDDoc(clientID)

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to fetch ClientID doc")
	}

	// TODO(jeremy): Verify that ClientURI is localhost or 127.0.0.1?
	listener, err := net.Listen("tcp", doc.ClientURI)

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, oidcProviderUri)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create new provider")
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID: clientID,
		Endpoint: provider.Endpoint(),
		// N.B. keep this in sync with the client id document
		RedirectURL: doc.RedirectURIs[0],
		Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}

	s, err := NewServer(config, verifier, listener, log)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create server")
	}

	// Run the server in a background thread.
	go func() {
		s.StartAndBlock()
	}()

	h := &SolidOIDCHelper{
		config: &config,
		Log:    log,
	}
	return h, nil
}

// GetTokenSource requests a token from the web, then returns the retrieved token.
func (h *SolidOIDCHelper) GetTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	authURL := h.config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)

	// TODO(jlewi): How to open it automatically?
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		return nil, errors.Wrapf(err, "Unable to read authorization code")
	}

	tok, err := h.config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to retrieve token from web")
	}

	return h.config.TokenSource(ctx, tok), nil
}

func (h *SolidOIDCHelper) GetOAuthConfig() *oauth2.Config {
	return h.config
}

func fetchClientIDDoc(clientID string) (*ClientIDDoc, error) {
	resp, err := http.Get(clientID)

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to fetch ClientID; %v", clientID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Failed to fetch ClientID; %v", clientID)
	}

	dec := json.NewDecoder(resp.Body)

	doc := &ClientIDDoc{}

	err = dec.Decode(doc)

	if err != nil {
		return nil, errors.Errorf("Failed to decode ClientIDDoc from body; %v", clientID)
	}

	return doc, nil
}
