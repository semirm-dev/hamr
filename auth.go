package hamr

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gobackpack/jwt"
	"github.com/google/uuid"

	"github.com/semirm-dev/hamr/internal/env"
	"github.com/semirm-dev/hamr/internal/str"
	"github.com/semirm-dev/hamr/oauth"
)

/*
	Main module.
	Responsible for tokens (access, refresh), claims and sessions.
*/

type Auth[T any] struct {
	conf                  *Config
	storage               TokenStorage
	getUserDetailsByEmail GetUserDetailsFunc[T]
	providers             []oauth.Provider
}

type Config struct {
	Host               string
	Port               string
	AccessTokenSecret  []byte
	AccessTokenExpiry  time.Duration
	RefreshTokenSecret []byte
	RefreshTokenExpiry time.Duration

	basePath string
	authPath string
}

type UserDetails[T any] struct {
	ID T
}

type TokenStorage interface {
	Store(item ...*Item) error
	Load(key string) ([]byte, error)
	Delete(key ...string) error
}

type Item struct {
	Key        string
	Value      interface{}
	Expiration time.Duration
}

type Option[T any] func(*Auth[T])
type GetUserDetailsFunc[T any] func(email string) UserDetails[T]

// TokenDetails holds access and refresh token details.
type TokenDetails struct {
	AccessToken        string
	RefreshToken       string
	accessTokenUuid    string
	accessTokenExpiry  time.Duration
	refreshTokenUuid   string
	refreshTokenExpiry time.Duration
}

// TokenClaims contains required claims for authentication (sub + email). Validated in: validateClaims(claims TokenClaims).
// These claims will be generated in access and refresh tokens
type TokenClaims map[string]interface{}

func New[T any](storage TokenStorage, getUserDetails GetUserDetailsFunc[T], opts ...Option[T]) *Auth[T] {
	conf := NewConfig()
	conf.Host = strings.Trim(conf.Host, "/")
	conf.basePath = conf.Host + ":" + conf.Port
	conf.authPath = conf.basePath + "/auth"

	auth := &Auth[T]{
		storage:               storage,
		conf:                  conf,
		getUserDetailsByEmail: getUserDetails,
	}

	for _, o := range opts {
		o(auth)
	}

	return auth
}

func NewConfig() *Config {
	return &Config{
		Host:               env.Get("AUTH_HOST", "http://localhost"),
		Port:               "8080",
		AccessTokenSecret:  []byte(str.Random(16)),
		AccessTokenExpiry:  time.Minute * 15,
		RefreshTokenSecret: []byte(str.Random(16)),
		RefreshTokenExpiry: time.Hour * 24 * 7,
	}
}

func WithProvider[T any](provider oauth.Provider) Option[T] {
	return func(a *Auth[T]) {
		a.providers = append(a.providers, provider)
	}
}

func WithConfig[T any](conf *Config) Option[T] {
	return func(a *Auth[T]) {
		a.conf = conf
	}
}

func (auth *Auth[T]) GetClaimsFromRequest(r *http.Request) (TokenClaims, error) {
	accessToken, err := getAccessTokenFromRequest(r)
	if err != nil {
		return nil, err
	}

	claims, err := auth.extractAccessTokenClaims(accessToken)
	if claims == nil || err != nil {
		return nil, errors.New("invalid access token claims")
	}

	return claims, nil
}

// createSession will create login session.
// Generate access and refresh tokens and save both tokens in cache storage.
func (auth *Auth[T]) createSession(claims TokenClaims) (TokenDetails, error) {
	if err := validateClaims(claims); err != nil {
		return TokenDetails{}, err
	}

	td, err := auth.generateTokens(claims)
	if err != nil {
		return TokenDetails{}, err
	}

	if err = auth.storeTokensInCache(claims["sub"], td); err != nil {
		return TokenDetails{}, err
	}

	return td, nil
}

// generateTokens will generate a pair of access and refresh tokens.
func (auth *Auth[T]) generateTokens(claims TokenClaims) (TokenDetails, error) {
	accessTokenUuid, accessTokenValue, err := generateToken(auth.conf.AccessTokenSecret, auth.conf.AccessTokenExpiry, claims)
	if err != nil {
		return TokenDetails{}, err
	}

	refreshTokenUuid, refreshTokenValue, err := generateToken(auth.conf.RefreshTokenSecret, auth.conf.RefreshTokenExpiry, claims)
	if err != nil {
		return TokenDetails{}, err
	}

	return TokenDetails{
		AccessToken:        accessTokenValue,
		RefreshToken:       refreshTokenValue,
		accessTokenUuid:    accessTokenUuid,
		accessTokenExpiry:  auth.conf.AccessTokenExpiry,
		refreshTokenUuid:   refreshTokenUuid,
		refreshTokenExpiry: auth.conf.RefreshTokenExpiry,
	}, nil
}

// storeTokensInCache will save access and refresh tokens in cache.
func (auth *Auth[T]) storeTokensInCache(sub interface{}, td TokenDetails) error {
	// cross-reference properties are created, so we can later easily find connection between access and refresh tokens
	// it's needed for easier cleanup on logout and refresh/token

	accessTokenCacheValue := TokenClaims{
		"sub":                sub,
		"refresh_token_uuid": td.refreshTokenUuid,
	}
	refreshTokenCacheValue := TokenClaims{
		"sub":               sub,
		"access_token_uuid": td.accessTokenUuid,
	}

	return auth.storage.Store(
		&Item{
			Key:        td.accessTokenUuid,
			Value:      accessTokenCacheValue,
			Expiration: td.accessTokenExpiry,
		}, &Item{
			Key:        td.refreshTokenUuid,
			Value:      refreshTokenCacheValue,
			Expiration: td.refreshTokenExpiry,
		})
}

// destroySession will remove access and refresh tokens from cache.
func (auth *Auth[T]) destroySession(accessToken string) error {
	accessTokenClaims, err := auth.extractAccessTokenClaims(accessToken)
	if err != nil {
		return err
	}

	accessTokenUuid := accessTokenClaims["uuid"]
	if accessTokenUuid == nil {
		return errors.New("invalid claims from access_token")
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		return err
	}

	refreshTokenUuid, ok := accessTokenCached["refresh_token_uuid"]
	if !ok {
		return errors.New("refresh_token_uuid not found in cached access_token")
	}

	return auth.storage.Delete(accessTokenUuid.(string), refreshTokenUuid.(string))
}

// extractAccessTokenClaims will validate and extract access token claims. Access token secret is used for validation.
func (auth *Auth[T]) extractAccessTokenClaims(accessToken string) (TokenClaims, error) {
	return extractToken(accessToken, auth.conf.AccessTokenSecret)
}

// extractRefreshTokenClaims will validate and extract refresh token. Refresh token secret is used for validation.
func (auth *Auth[T]) extractRefreshTokenClaims(refreshToken string) (TokenClaims, error) {
	return extractToken(refreshToken, auth.conf.RefreshTokenSecret)
}

// getTokenFromCache will get and unmarshal token from cache.
func (auth *Auth[T]) getTokenFromCache(tokenUuid string) (TokenClaims, error) {
	cachedTokenBytes, err := auth.storage.Load(tokenUuid)
	if err != nil {
		return nil, errors.New("token is no longer active")
	}

	var cachedToken TokenClaims
	if err = json.Unmarshal(cachedTokenBytes, &cachedToken); err != nil {
		return nil, errors.New("getTokenFromCache unmarshal failed: " + err.Error())
	}

	return cachedToken, nil
}

// validateClaims will check for required TokenClaims.
func validateClaims(claims TokenClaims) error {
	_, ok := claims["sub"]
	if !ok {
		return errors.New("missing sub from claims")
	}

	_, ok = claims["email"]
	if !ok {
		return errors.New("missing email from claims")
	}

	return nil
}

// generateAuthClaims for access token.
func generateAuthClaims(sub any, email string) TokenClaims {
	claims := make(TokenClaims)
	claims["sub"] = sub
	claims["email"] = email

	return claims
}

// generateToken is used for both access and refresh token.
// It will generate token value and uuid.
// Can be split into two separate functions if needed (ex. different claims used).
func generateToken(tokenSecret []byte, tokenExpiry time.Duration, claims TokenClaims) (string, string, error) {
	token := &jwt.Token{
		Secret: tokenSecret,
	}

	tClaims := make(TokenClaims)
	for k, v := range claims {
		tClaims[k] = v
	}
	tUuid := uuid.New().String()
	tClaims["exp"] = jwt.TokenExpiry(tokenExpiry)
	tClaims["uuid"] = tUuid

	tValue, err := token.Generate(tClaims)
	if err != nil {
		return "", "", err
	}

	return tUuid, tValue, nil
}

// extractToken will validate and extract claims from given token
func extractToken(token string, secret []byte) (TokenClaims, error) {
	jwtToken := &jwt.Token{
		Secret: secret,
	}

	return jwtToken.Validate(token)
}

// getAccessTokenFromRequest will extract access token from request's Authorization headers.
// Returns schema and access_token.
func getAccessTokenFromRequest(r *http.Request) (string, error) {
	authHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authHeader) != 2 {
		return "", errors.New("invalid authorization headers")
	}

	schema, token := authHeader[0], authHeader[1]
	if schema != "Bearer" {
		return "", errors.New("unsupported authorization schema")
	}

	if strings.TrimSpace(token) == "" {
		return "", errors.New("access token not found in headers")
	}

	return token, nil
}
