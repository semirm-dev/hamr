package main

import (
	"net/http"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/semirm-dev/hamr"
)

func MapAuthRoutesGin[T any](auth *hamr.Auth[T], router *gin.Engine) {
	r := router.Group("/api/auth")

	r.GET(":provider/login", func(c *gin.Context) {
		provider := c.Param("provider")

		if err := auth.OAauthLoginHandler(provider, c.Writer, c.Request); err != nil {
			logrus.Error(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	r.GET(":provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")

		tokens, err := auth.OAuthLoginCallbackHandler(c.Request.Context(), provider, c.Request)
		if err != nil {
			logrus.Error(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.JSON(http.StatusOK, tokens)
	})
}

func Authorized[T any](auth *hamr.Auth[T]) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := auth.Authorized(c.Request); err != nil {
			logrus.Error(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.Next()
	}
}

func AuthorizedCasbin[T any](auth *hamr.Auth[T], obj, act string) gin.HandlerFunc {
	db, err := hamr.PostgresDb("host=localhost port=5432 dbname=webapp user=postgres password=postgres sslmode=disable")
	if err != nil {
		logrus.Fatal(err)
	}

	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		logrus.Fatal("failed to initialize casbin adapter: ", err)
	}
	policy := casbinPolicyModel()

	return func(c *gin.Context) {
		if err = auth.AuthorizedWithCasbin(obj, act, policy, adapter, c.Request); err != nil {
			logrus.Error(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.Next()
	}
}

func casbinPolicyModel() string {
	return `
		[request_definition]
		r = sub, obj, act
		
		[policy_definition]
		p = sub, obj, act
		
		[role_definition]
		g = _, _
		
		[policy_effect]
		e = some(where (p.eft == allow))
		
		[matchers]
		m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
	`
}
