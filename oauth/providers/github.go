package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/semirm-dev/hamr/oauth"
)

// GitHub oauth provider implementation
type GitHub struct {
	clientId     string
	clientSecret string
}

type githubResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func NewGitHub(clientId, clientSecret string) *GitHub {
	return &GitHub{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

func (p *GitHub) Name() string {
	return "github"
}

func (p *GitHub) ClientId() string {
	return p.clientId
}

func (p *GitHub) ClientSecret() string {
	return p.clientSecret
}

func (p *GitHub) Scopes() []string {
	return []string{"user:email"}
}

func (p *GitHub) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (p *GitHub) GetUserInfo(accessToken string) (*oauth.UserInfo, error) {
	exchangeUrl := "https://api.github.com/user"

	req, err := http.NewRequest("GET", exchangeUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "token "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logrus.Error("failed to close code exchange http response: ", err.Error())
			return
		}
	}()

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r := &githubResponse{}
	if err = json.Unmarshal(contents, &r); err != nil {
		return nil, err
	}

	return &oauth.UserInfo{
		ExternalId: fmt.Sprint(r.Id),
		Email:      r.Email,
	}, nil
}
