package oauthext

import (
	"encoding/json"
	"os"
	"path"
	"testing"
)

// Test_ClientIdDoc verifies json documents can be successful unmarshaled into the struct
func Test_ClientIdDoc(t *testing.T) {
	type testCase struct {
		file string
	}

	cases := []testCase{
		{
			file: "clientid.json",
		},
	}

	testDir, err := os.Getwd()

	if err != nil {
		t.Fatalf("Failed to get current directory")
	}

	dataDir := path.Join(testDir, "test_data")

	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f := path.Join(dataDir, c.file)

			r, err := os.Open(f)
			defer r.Close()
			if err != nil {
				t.Fatalf("Failed to open file: %v", f)
			}

			doc := &ClientIDDoc{}

			dec := json.NewDecoder(r)
			err = dec.Decode(doc)
			if err != nil {
				t.Fatalf("Failed to decode ClientID doc; error %v", err)
			}
		})
	}
}
