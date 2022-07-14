package oauthext

type ClientIDDoc struct {
	Context                []string `json:"@context"`
	ClientID               string   `json:"client_id"`
	ClientName             string   `json:"client_name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	ClientURI              string   `json:"client_uri"`
	LogoURI                string   `json:"logo_uri"`
	TosURI                 string   `json:"tos_uri"`
	Scope                  string   `json:"scope"`
	GrantTypes             []string `json:"grant_types"`
	ResponseTypes          []string `json:"response_types"`
	DefaultMaxAge          int      `json:"default_max_age"`
	RequireAuthTime        bool     `json:"require_auth_time"`
}
