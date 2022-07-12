package main

import (
	"context"
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

func newGetCmd() *cobra.Command {
	var port int
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

	return cmd
}

func main() {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newRdfTestCmd())
	rootCmd.Execute()
}
