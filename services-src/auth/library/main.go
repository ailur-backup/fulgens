package library

type OAuthInformation struct {
	Token       string   `json:"token"`
	Name        string   `json:"name"`
	RedirectUri string   `json:"redirectUri"`
	KeyShareUri string   `json:"keyShareUri"`
	Scopes      []string `json:"scopes"`
}

type OAuthResponse struct {
	AppID     string `json:"appId"`
	SecretKey string `json:"secretKey"`
}
