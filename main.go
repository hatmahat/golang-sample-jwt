package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"net/http"
)

type AuthHeader struct {
	Authorization string `header:"Authorization"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	ApplicationName = "Enigma"
	JwtSigninMethod = jwt.SigningMethodES256
	JwtSignatureKey = []byte("3N!GM4")
)

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Email    string `json:"email"`
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

func GenerateToken(userName string, email string) (string, error) {
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: ApplicationName,
		},
		Username: userName,
		Email:    email,
	}
	token := jwt.NewWithClaims(
		JwtSigninMethod,
		claims)
	return token.SignedString(JwtSignatureKey)
}

func ParseToke(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("signin method invalid")
		} else if method != JwtSigninMethod {
			return nil, fmt.Errorf("signin method invalid")
		}
		return JwtSignatureKey, nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}
