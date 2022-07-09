package main

import (
	"fmt"
	"github.com/deiu/rdf2go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newRdfTestCmd() *cobra.Command {
	var file string
	var uri string
	cmd := &cobra.Command{
		Short: "Test reading/writing RDF files",
		Use:   "rdftest",
		Run: func(cmd *cobra.Command, args []string) {
			err := func() error {
				// Set a base URI
				baseUri := "https://acme.co/foo"

				// Do not skip verfication of remote certificates (i.e. don't accept self-signed)
				skipVerify := false
				// Create a new graph
				g := rdf2go.NewGraph(baseUri, skipVerify)

				err := g.LoadURI(uri)
				if err != nil {
					return errors.Wrapf(err, "Could not open uri: %v", uri)
				}
				//triple := rdf2go.NewTriple(rdf2go.NewResource("a"), rdf2go.NewResource("b"), rdf2go.NewResource("c"))
				//g.Add(triple)
				//
				//f, err := os.Create(file)
				//if err != nil {
				//	return errors.Wrapf(err, "Could not open file: %v", f)
				//}
				//defer f.Close()
				//
				//log.Info("Serializing graph", "file", file)
				//if err := g.Serialize(f, "text/turtle"); err != nil {
				//	return errors.Wrapf(err, "Failed to serialize the graph")
				//}
				log.Info("Read graph:\n", "graph", g.String())
				return nil
			}()

			if err != nil {
				log.Error(err, fmt.Sprintf("Failed to run commands: %+v", err))
			}
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "The RDF file to read and write")
	cmd.Flags().StringVarP(&uri, "uri", "u", "", "The URI to read/write")
	return cmd
}
