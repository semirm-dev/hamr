package hamr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

// Authorized middleware will check if the request is authorized.
func (auth *Auth[T]) Authorized(r *http.Request) error {
	_, err := auth.authorize(r)
	return err
}

// AuthorizedWithCasbin middleware will check if the request is authorized applying Casbin policy too.
func (auth *Auth[T]) AuthorizedWithCasbin(obj, act, policy string, adapter *gormadapter.Adapter, r *http.Request) error {
	id, err := auth.authorize(r)
	if err != nil {
		return err
	}

	if policyOk, policyErr := enforce(id, obj, act, policy, adapter); policyErr != nil || !policyOk {
		return errors.New(fmt.Sprintf("casbin policy not passed, err: %s", policyErr))
	}

	return nil
}

func (auth *Auth[T]) authorize(r *http.Request) (interface{}, error) {
	claims, err := auth.GetClaimsFromRequest(r)
	if err != nil {
		return nil, err
	}

	userIdFromRequestClaims := claims["sub"]
	accessTokenUuid := claims["uuid"]
	if userIdFromRequestClaims == nil || accessTokenUuid == nil {
		return nil, errors.New("userId or accessTokenUuid is nil")
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to get access token from cache: %s", err))
	}

	userIdFromCacheClaims, ok := accessTokenCached["sub"]
	if !ok {
		return nil, errors.New("sub not found in accessTokenCached")
	}

	if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
		return nil, errors.New("userIdFromRequestClaims does not match userIdFromCacheClaims")
	}

	return userIdFromRequestClaims, nil
}

func enforce(sub any, obj, act, policy string, adapter *gormadapter.Adapter) (bool, error) {
	m, err := model.NewModelFromString(policy)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin model from string: %s", err)
	}

	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin enforcer: %s", err)
	}

	err = enforcer.LoadPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to load casbin policy from database: %s", err)
	}

	return enforcer.Enforce(sub, obj, act)
}
