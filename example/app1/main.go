package main

import (
	"flag"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/semirm-dev/hamr"
	"github.com/semirm-dev/hamr/internal/env"
	"github.com/semirm-dev/hamr/internal/web"
	"github.com/semirm-dev/hamr/oauth/providers"
)

func main() {
	flag.Parse()

	opts := []hamr.Option[uint]{
		hamr.WithProvider[uint](providers.NewGoogle(
			env.Get("GOOGLE_CLIENT_ID", ""),
			env.Get("GOOGLE_CLIENT_SECRET", ""))),
	}
	auth := hamr.New(hamr.NewRedisCacheStorage(
		"",
		"6379",
		"",
		0), func(email string) hamr.UserDetails[uint] {
		return hamr.UserDetails[uint]{
			ID: 1,
		}
	}, opts...)

	router := web.NewGinRouter()
	MapAuthRoutesGin(auth, router)

	//example #1: protected without roles/policy
	{
		router.GET("protected", Authorized(auth), func(ctx *gin.Context) {
			claims, err := auth.GetClaimsFromRequest(ctx.Request)
			if err != nil {
				logrus.Error(err)
				ctx.AbortWithStatus(http.StatusUnauthorized)
			}

			ctx.JSON(http.StatusOK, claims)
		})
	}

	//example #1: protected with Casbin roles/policy
	{
		router.GET("protected/v2", AuthorizedCasbin(auth, "res", ""), func(ctx *gin.Context) {
			claims, err := auth.GetClaimsFromRequest(ctx.Request)
			if err != nil {
				logrus.Error(err)
				ctx.AbortWithStatus(http.StatusUnauthorized)
			}

			ctx.JSON(http.StatusOK, claims)
		})
	}

	web.ServeHttp(":8080", router)
}
