package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/semirm-dev/hamr/oauth"
)

// Google oauth provider implementation
type Google struct {
	clientId     string
	clientSecret string
}

type googleResponse struct {
	Id    string `json:"id"`
	Email string `json:"email"`
}

func NewGoogle(clientId, clientSecret string) *Google {
	return &Google{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (p *Google) Name() string {
	return "google"
}

func (p *Google) ClientId() string {
	return p.clientId
}

func (p *Google) ClientSecret() string {
	return p.clientSecret
}

func (p *Google) Scopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func (p *Google) Endpoint() oauth2.Endpoint {
	return google.Endpoint
}

func (p *Google) GetUserInfo(accessToken string) (*oauth.UserInfo, error) {
	exchangeUrl := "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken

	res, err := http.Get(exchangeUrl)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			logrus.Error("failed to close code exchange http response: ", err.Error())
			return
		}
	}()

	contents, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	r := &googleResponse{}
	if err = json.Unmarshal(contents, &r); err != nil {
		return nil, err
	}

	return &oauth.UserInfo{
		ExternalId: r.Id,
		Email:      r.Email,
	}, nil
}
