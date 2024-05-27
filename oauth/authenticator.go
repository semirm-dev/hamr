package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	oAuthLoginAntiForgeryKey = "externalLoginAntiForgery"
	stateExpiry              = time.Minute * 2
)

// Authenticator is responsible for oauth logins, oAuth2 configuration setup.
type Authenticator struct {
	provider Provider
	conf     *oauth2.Config
}

// Provider specific requirements.
type Provider interface {
	Credentials
	Name() string
	Scopes() []string
	Endpoint() oauth2.Endpoint
	GetUserInfo(string) (*UserInfo, error)
}

// Credentials for Providers.
type Credentials interface {
	ClientId() string
	ClientSecret() string
}

// UserInfo from oauth provider.
type UserInfo struct {
	ExternalId string
	Email      string
}

// NewAuthenticator will set up Authenticator, oAuth2 configuration.
func NewAuthenticator(baseAuthPath string, provider Provider) (*Authenticator, error) {
	redirectUrl := baseAuthPath + "/" + provider.Name() + "/callback"

	return newAuthenticator(provider, redirectUrl)
}

func newAuthenticator(provider Provider, redirectUrl string) (*Authenticator, error) {
	auth := &Authenticator{
		provider: provider,
		conf: &oauth2.Config{
			ClientID:     provider.ClientId(),
			ClientSecret: provider.ClientSecret(),
			RedirectURL:  redirectUrl,
			Scopes:       provider.Scopes(),
			Endpoint:     provider.Endpoint(),
		},
	}

	return auth, nil
}

// RedirectToLoginUrl from oauth provider.
func (a *Authenticator) RedirectToLoginUrl(w http.ResponseWriter, r *http.Request) error {
	oAuthState, err := setLoginAntiForgeryCookie(w)
	if err != nil {
		return err
	}

	oAuthLoginUrl := a.conf.AuthCodeURL(oAuthState)

	http.Redirect(w, r, oAuthLoginUrl, http.StatusTemporaryRedirect)
	return nil
}

// GetUserInfo from oauth provider.
func (a *Authenticator) GetUserInfo(ctx context.Context, r *http.Request) (*UserInfo, error) {
	token, err := a.exchangeCodeForToken(ctx, r)
	if err != nil {
		logrus.Errorf("failed to exchange code for token: %v", err)
		return nil, errors.New("failed to get token from oauth provider")
	}

	userInfo, err := a.provider.GetUserInfo(token.AccessToken)
	if err != nil {
		logrus.Errorf("failed to get user info from oauth provider: %v", err)
		return nil, errors.New("failed to get user info from oauth provider")
	}

	return userInfo, nil
}

// exchangeCodeForToken will validate state and exchange code for oauth token.
func (a *Authenticator) exchangeCodeForToken(ctx context.Context, r *http.Request) (*oauth2.Token, error) {
	oAuthStateSaved, oAuthStateErr := r.Cookie(oAuthLoginAntiForgeryKey)
	oAuthState := r.FormValue("state")
	oAuthStateCode := r.FormValue("code")

	if oAuthStateErr != nil || oAuthState == "" {
		return nil, errors.New("invalid oAuthStateSaved/oAuthState")
	}

	if oAuthState != oAuthStateSaved.Value {
		return nil, errors.New("oAuthState do not match")
	}

	token, err := a.conf.Exchange(ctx, oAuthStateCode)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// setLoginAntiForgeryCookie will generate random state string and save it in cookies.
// This is for CSRF protection.
func setLoginAntiForgeryCookie(w http.ResponseWriter) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	var expiration = time.Now().Add(stateExpiry)

	cookie := http.Cookie{Name: oAuthLoginAntiForgeryKey, Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state, nil
}
