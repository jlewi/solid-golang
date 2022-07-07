package main

import (
	"fmt"
	"github.com/go-logr/logr"
	"github.com/jlewi/p22h/backend/pkg/logging"
	"github.com/spf13/cobra"
	"io/ioutil"
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
	cmd := &cobra.Command{
		Short: "get contents of a pod",
		Use:   "get",
		Run: func(cmd *cobra.Command, args []string) {

			err := func() error {
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
	return cmd
}

func main() {
	rootCmd := newRootCmd()
	rootCmd.AddCommand(newGetCmd())
	rootCmd.Execute()
}
