package oauthext

import (
	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_fetchClientID(t *testing.T) {
	type testCase struct {
		uri      string
		response ClientIDDoc
	}

	testCases := []testCase{
		{
			uri: "http://some/doc",
			response: ClientIDDoc{
				ClientID:     "someid",
				ClientName:   "somename",
				RedirectURIs: []string{"someuri"},
				ClientURI:    "http://some/doc",
			},
		},
	}

	for _, c := range testCases {
		t.Run(c.uri, func(t *testing.T) {
			// Start a local HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				enc := json.NewEncoder(rw)
				if err := enc.Encode(c.response); err != nil {
					t.Fatalf("Failed to encode response; error: %v", err)
				}
			}))
			// Close the server when test finishes
			defer server.Close()

			// Use Client & URL from our local test server
			actual, err := fetchClientIDDoc(server.URL)

			if err != nil {
				t.Fatalf("fetchClientIDDoc failed; error: %v", err)
			}

			if d := cmp.Diff(c.response, *actual); d != "" {
				t.Errorf("Unexpected response; diff:\n%v", d)
			}
		})
	}
}
