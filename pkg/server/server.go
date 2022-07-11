package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/gorilla/mux"
	"github.com/jlewi/p22h/backend/api"
	"github.com/jlewi/p22h/backend/pkg/debug"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"time"
)

// Server creates a server to be used as part of client registration in the solid-oidc protocol.
// As discussed in https://solid.github.io/solid-oidc/#clientids the client
// identifies itself to the OIDC provider by presenting a URL
type Server struct {
	log      logr.Logger
	listener net.Listener
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewServer(config oauth2.Config, verifier *oidc.IDTokenVerifier, listener net.Listener, log logr.Logger) (*Server, error) {
	if listener == nil {
		return nil, errors.Errorf("listener must be set")
	}
	return &Server{
		log:      log,
		listener: listener,
		config:   config,
		verifier: verifier,
	}, nil
}

func (s *Server) Address() string {
	return fmt.Sprintf("http://localhost:%v", s.listener.Addr().(*net.TCPAddr).Port)
}

func (s *Server) writeStatus(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	resp := api.RequestStatus{
		Kind:    "RequestStatus",
		Message: message,
		Code:    code,
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(resp); err != nil {
		s.log.Error(err, "Failed to marshal RequestStatus", "RequestStatus", resp, "code", code)
	}

	if code != http.StatusOK {
		caller := debug.ThisCaller()
		s.log.Info("HTTP error", "RequestStatus", resp, "code", code, "caller", caller)
	}
}

func (s *Server) HealthCheck(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, "app server is running", http.StatusOK)
}

func (s *Server) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	s.writeStatus(w, fmt.Sprintf("feed backend server doesn't handle the path; url: %v", r.URL), http.StatusNotFound)
}

// StartAndBlock starts the server and blocks.
func (s *Server) StartAndBlock() error {
	log := s.log

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/", s.handleRoot)
	router.HandleFunc("/healthz", s.HealthCheck)
	router.HandleFunc("/auth/callback", s.handleAuthCallback)

	router.NotFoundHandler = http.HandlerFunc(s.NotFoundHandler)

	log.Info("Gateway is running", "address", s.Address())
	err := http.Serve(s.listener, router)

	if err != nil {
		log.Error(err, "Server returned error")
	}
	return err
}

// TODO(jeremy) What is the purpose of this function? It appears to set a cookie
// and then redirect?
// It was copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L65
// I think it might just be for the example its redirecting to the auth callback.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, s.config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// handleAuthCallback handles the OIDC auth callback code copied from
// https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L82.
//
// The Auth callback is invoked in step 21 of the OIDC protocol.
// https://solid.github.io/solid-oidc/primer/#:~:text=Solid%2DOIDC%20builds%20on%20top,authentication%20in%20the%20Solid%20ecosystem.
// The OpenID server responds with a 303 redirect to the AuthCallback URL and passes the authorization code.
// This is a mechanism for the authorization code to be passed into the code. 
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	oauth2Token.AccessToken = "*REDACTED*"

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// copied from: https://github.com/coreos/go-oidc/blob/2cafe189143f4a454e8b4087ef892be64b1c77df/example/idtoken/app.go#L34
func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
