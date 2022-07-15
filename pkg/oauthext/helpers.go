package oauthext

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

const (
	timeout = 5 * time.Minute
)

// SolidOIDCHelper implements the CredentialHelper interface defined in
// https://github.com/kubeflow/internal-acls/blob/master/google_groups/pkg/gcp/credentials.go#L28
type SolidOIDCHelper struct {
	config *oauth2.Config
	Log    logr.Logger
	s      *Server
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

	if !checkClientIDDoc(clientID, doc) {
		return nil, errors.Wrapf(err, "ClientID document is invalid; check logs for more information.")
	}

	u, err := url.Parse(doc.ClientURI)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse client URI; %v", doc.ClientURI)
	}

	listener, err := net.Listen("tcp", u.Host)

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create listener")
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, oidcProviderUri)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create new provider")
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	if len(doc.RedirectURIs) > 1 {
		log.Info("Warning; ClientID document has more than 1 RedirectURIs; the first one will be used", "uri", doc.RedirectURIs[0])
	}
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
		s:      s,
	}
	return h, nil
}

// GetTokenSource requests a token from the web, then returns the retrieved token.
func (h *SolidOIDCHelper) GetTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	h.Log.Info("Starting the OIDC web flow", "url", h.s.AuthStartURL())
	if err := openBrowser(h.s.AuthStartURL()); err != nil {
		h.Log.Error(err, "Failed to open URL automatically; try opening it manually in your browser", "url", h.s.AuthStartURL())
	}

	var tokSrc oauth2.TokenSource
	timeOut := time.Now().Add(timeout)
	wait := 5 * time.Second
	for {
		tokSrc = h.s.TokenSource()
		if tokSrc != nil {
			h.Log.Info("Authorization completed")
			return tokSrc, nil
		}

		if time.Now().Add(wait).After(timeOut) {
			return nil, errors.New("Timeout waiting for the Solid OIDC webflow to complete")
		} else {
			h.Log.Info("Waiting for authorization to complete")
			time.Sleep(5 * time.Second)
		}
	}
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

// openBrowser opens the provided URL in the browser.
func openBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	return err
}

// checkClientIDDoc run some validation tests on the ClientID doc to help discover invalid client id documents.
func checkClientIDDoc(uri string, doc *ClientIDDoc) bool {
	log := zapr.NewLogger(zap.L())
	isValid := true
	if uri != doc.ClientID {
		isValid = false
		log.Info("ClientID document is invalid; document is served at URL that doesn't match the client_uri field in the document", "uri", uri, "client_uri", doc.ClientID)
	}

	return isValid
}
