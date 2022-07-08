package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthHeader struct {
	Authorization string `header:"Authorization"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	routerEngine := gin.Default()
	routerGroup := routerEngine.Group("/api")

	routerGroup.GET("/customer", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		if err := ctx.ShouldBindHeader(&authHeader); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			return
		}

		if authHeader.Authorization == "87654321" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "customer",
			})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "token invalid",
		})
	})

	routerGroup.GET("/product", func(ctx *gin.Context) {
		authHeader := AuthHeader{}
		if err := ctx.ShouldBindHeader(&authHeader); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			return
		}

		if authHeader.Authorization == "87654321" {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "product",
			})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "token invalid",
		})
	})

	err := routerEngine.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
