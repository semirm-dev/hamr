package hamr

import (
	"context"
	"net/http"

	"github.com/semirm-dev/hamr/oauth"
)

// OAauthLoginHandler maps to :provider login route. Redirects to :provider oAuth login url.
func (auth *Auth[T]) OAauthLoginHandler(p string, w http.ResponseWriter, r *http.Request) error {
	provider := auth.getProvider(p)

	authenticator, err := oauth.NewAuthenticator(auth.conf.authPath, provider)
	if err != nil {
		return err
	}

	return authenticator.RedirectToLoginUrl(w, r)
}

// OAuthLoginCallbackHandler maps to :provider login callback route. After login :provider redirects to this route.
func (auth *Auth[T]) OAuthLoginCallbackHandler(ctx context.Context, p string, r *http.Request) (TokenDetails, error) {
	provider := auth.getProvider(p)

	authenticator, err := oauth.NewAuthenticator(auth.conf.authPath, provider)
	if err != nil {
		return TokenDetails{}, err
	}

	userInfo, err := authenticator.GetUserInfo(ctx, r)
	if err != nil {
		return TokenDetails{}, err
	}

	return auth.authenticateWithOAuth(userInfo)
}

// authenticateWithOAuth will log user with oauth provider (google, github...), save tokens in cache.
func (auth *Auth[T]) authenticateWithOAuth(userInfo *oauth.UserInfo) (TokenDetails, error) {
	email := userInfo.Email

	user := auth.getUserDetailsByEmail(email)

	claims := generateAuthClaims(user.ID, email)

	return auth.createSession(claims)
}

func (auth *Auth[T]) getProvider(providerName string) oauth.Provider {
	for _, p := range auth.providers {
		if p.Name() == providerName {
			return p
		}
	}

	return nil
}
