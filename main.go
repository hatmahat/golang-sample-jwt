package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
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

	routerGroup.POST("/auth/login", func(c *gin.Context) {
		var user Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}
		if user.Username == "enigma" && user.Password == "123" {
			token, err := GenerateToken(user.Username, "admin@enigmacamp.com")
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	routerGroup.GET("/customer", func(ctx *gin.Context) {
		// authHeader := AuthHeader{}
		// if err := ctx.ShouldBindHeader(&authHeader); err != nil {
		// 	ctx.JSON(http.StatusUnauthorized, gin.H{
		// 		"message": "Unauthorized",
		// 	})
		// 	return
		// }

		// if authHeader.Authorization == "87654321" {
		// 	ctx.JSON(http.StatusOK, gin.H{
		// 		"message": "customer",
		// 	})
		// 	return
		// }
		// ctx.JSON(http.StatusUnauthorized, gin.H{
		// 	"message": "token invalid",
		// })

		ctx.JSON(http.StatusOK, gin.H{
			"message": "customer",
		})
	})

	routerGroup.GET("/product", func(ctx *gin.Context) {
		// authHeader := AuthHeader{}
		// if err := ctx.ShouldBindHeader(&authHeader); err != nil {
		// 	ctx.JSON(http.StatusUnauthorized, gin.H{
		// 		"message": "Unauthorized",
		// 	})
		// 	return
		// }

		// if authHeader.Authorization == "87654321" {
		// 	ctx.JSON(http.StatusOK, gin.H{
		// 		"message": "product",
		// 	})
		// 	return
		// }
		// ctx.JSON(http.StatusUnauthorized, gin.H{
		// 	"message": "token invalid",
		// })

		ctx.JSON(http.StatusOK, gin.H{
			"message": "prduct",
		})
	})

	err := routerEngine.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

func AuthTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/api/auth/login" {
			c.Next()
			fmt.Println("sss")
		} else {
			h := AuthHeader{}
			if err := c.ShouldBindHeader(&h); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}

			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer", "", -1)
			fmt.Println("tokenString: ", tokenString)
			if h.AuthorizationHeader == "123456" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}

			token, err := ParseToken(tokenString)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}
			fmt.Println("token: ", token)
			if token["iss"] == ApplicationName {
				c.Next()
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}
		}
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

func ParseToken(tokenString string) (jwt.MapClaims, error) {
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
