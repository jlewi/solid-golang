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

				//webId := "https://pod.inrupt.com/jeremylewi/profile/card#me"
				log.Info("fetching credentials", "webId")
				// TODO need to discover the oidc provider by reading the WebId profile.
				// https://solid.github.io/solid-oidc/#oidc-issuer-discovery
				oidcProviderUri := "https://broker.pod.inrupt.com/"
				ctx := context.Background()

				provider, err := oidc.NewProvider(ctx, oidcProviderUri)
				if err != nil {
					return errors.Wrapf(err, "Failed to create new provider")
				}

				// We host the Client ID document using github.
				clientID := "https://raw.githubusercontent.com/jlewi/solid-golang/main/id/clientid"
				oidcConfig := &oidc.Config{
					ClientID: clientID,
				}
				verifier := provider.Verifier(oidcConfig)

				config := oauth2.Config{
					ClientID: clientID,
					//ClientSecret: clientSecret,
					Endpoint: provider.Endpoint(),
					// N.B. keep this in sync with the client id document
					RedirectURL: "http://localhost:9080/auth/callback",
					Scopes:      []string{oidc.ScopeOpenID},
				}

				s, err := server.NewServer(config, verifier, listener, log)
				if err != nil {
					return errors.Wrapf(err, "Failed to start server")
				}

				s.StartAndBlock()
				r, err := http.Get("https://pod.inrupt.com/jeremylewi/contacts/")

				if err != nil {
					return err
				}

				if r.StatusCode != http.StatusOK {
					body, readErr := ioutil.ReadAll(r.Body)

					if readErr != nil {
						log.Error(err, "Failed to read response body")
					}
					log.Info("List request failed", "status", r.StatusCode, "body", string(body))
					return nil
				}
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
	rootCmd.Execute()
}
