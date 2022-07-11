package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"github.com/jlewi/solid-golang/pkg/server"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

var (
	log logr.Logger
)

func newRootCmd() *cobra.Command {
	var level string
	var debug bool
	rootCmd := &cobra.Command{
		Short: "CLI for working with solid protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			newLogger, err := logging.InitLogger(level, debug)
			if err != nil {
				panic(err)
			}
			log = *newLogger
		},
	}
	rootCmd.PersistentFlags().StringVarP(&level, "level", "", "info", "The logging level.")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "Enable debug mode for logs.")

	return rootCmd
}

type OAuthClientInfo struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func newGetCmd() *cobra.Command {
	var port int
	var clientFile string
	cmd := &cobra.Command{
		Short: "get contents of a pod",
		Use:   "get",
		Run: func(cmd *cobra.Command, args []string) {

			err := func() error {
				listener, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
				if err != nil {
					return errors.Wrapf(err, "Failed to listen on port %v", port)
				}

				webId := "https://pod.inrupt.com/jeremylewi/profile/card#me"
				log.Info("fetching credentials", "webId", webId)
				// TODO need to discover the oidc provider by reading the WebId profile.
				// https://solid.github.io/solid-oidc/#oidc-issuer-discovery
				oidcProviderUri := "https://broker.pod.inrupt.com/"
				ctx := context.Background()

				provider, err := oidc.NewProvider(ctx, oidcProviderUri)
				if err != nil {
					return errors.Wrapf(err, "Failed to create new provider")
				}

				// We host the Client ID document in a solid pod.
				clientID := "https://pod.inrupt.com/jeremylewi/public/clientids/clientid01.json"
				oidcConfig := &oidc.Config{
					ClientID: clientID,
				}
				verifier := provider.Verifier(oidcConfig)

				config := oauth2.Config{
					ClientID: clientID,
					//ClientSecret: clientSecret,
					Endpoint: provider.Endpoint(),
					// N.B. keep this in sync with the client id document
					RedirectURL: fmt.Sprintf("http://localhost:%v/auth/callback", port),
					Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				}

				// TODO(jeremy): I think we can delete this code.
				if clientFile != "" {
					log.Info("Loading client id and secret", "file", clientFile)

					b, err := ioutil.ReadFile(clientFile)
					if err != nil {
						return errors.Wrapf(err, "Failed to read file: %v", clientFile)
					}

					info := &OAuthClientInfo{}
					err = json.Unmarshal(b, info)
					if err != nil {
						return errors.Wrapf(err, "Failed to unmarshal client file to OAuthClientInfo")
					}
					config.ClientID = info.ClientID
					config.ClientSecret = info.ClientSecret
					// I'm getting invalid redirect_uri this was an attempt to fix this.
					config.RedirectURL = fmt.Sprintf("http://127.0.0.1:%v", port)
				}

				s, err := server.NewServer(config, verifier, listener, log)
				if err != nil {
					return errors.Wrapf(err, "Failed to start server")
				}

				// Run the server in a background thread.
				go func() {
					s.StartAndBlock()
				}()

				// TODO(jeremy): How can we automatically open this up in the web browser
				fmt.Printf("Login in at: %v", fmt.Sprintf("http://localhost:%v", port))

				var tokSrc oauth2.TokenSource
				for {
					tokSrc = s.TokenSource()
					if tokSrc == nil {
						log.Info("Waiting for authorization to complete")
						time.Sleep(5 * time.Second)
					} else {
						log.Info("Authorization completed")
						break
					}
				}

				c := oauth2.NewClient(context.Background(), tokSrc)

				r, err := c.Get("https://pod.inrupt.com/jeremylewi/private/sample.txt")
				if err != nil {
					return err
				}
				body, readErr := ioutil.ReadAll(r.Body)

				if readErr != nil {
					log.Error(err, "Failed to read response body")
				}
				if r.StatusCode != http.StatusOK {
					log.Info("Get request failed", "status", r.StatusCode, "body", string(body))
					return nil
				}

				log.Info("Response succeeded", "body", string(body))
				return nil
			}()

			if err != nil {
				log.Error(err, fmt.Sprintf("Failed to run commands: %+v", err))
			}

		},
	}
	cmd.Flags().IntVarP(&port, "port", "p", 9080, "Port to serve on")
	cmd.Flags().StringVarP(&clientFile, "client-path", "", "", "If supplied should be a JSON file containing client id and secret")

	return cmd
}

func main() {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newRdfTestCmd())
	rootCmd.Execute()
}
