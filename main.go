package main

import (
	"golang-sample-jwt/config"
	"golang-sample-jwt/delivery/middleware"
	"golang-sample-jwt/model"
	"golang-sample-jwt/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	//"github.com/go-redis/redis"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

//type Credential struct {
//	Username string `json:"username"`
//	Password string `json:"password"`
//}
//
//var (
//	ApplicationName = "Enigma"
//	JwtSinginMethod = jwt.SigningMethodHS256
//	JwtSignatureKey = []byte("3N!GM4")
//)

//type MyClaims struct {
//	jwt.StandardClaims
//	Username string `json:"username"`
//	Email    string `json:"email"`
//}

func main() {
	routerEngine := gin.Default()

	// redis config
	// client := redis.NewClient(&redis.Options{
	// 	Addr:     "localhost",
	// 	Password: "",
	// 	DB:       0,
	// })

	cfg := config.NewConfig()
	tokenService := utils.NewTokenService(cfg.TokenConfig)
	routerGroup := routerEngine.Group("/api")
	routerGroup.POST("/auth/login", func(c *gin.Context) {
		var user model.Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}
		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			err = tokenService.StoreAccessToken(user.Username, token)
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	protectedGroup := routerGroup.Group("/master", middleware.NewTokenValidator(tokenService).RequireToken())
	protectedGroup.GET("/customer", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.Get("user-id"),
		})
	})

	protectedGroup.GET("/product", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "product",
		})
	})

	err := routerEngine.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

// func AuthTokenMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		if c.Request.URL.Path == "/api/auth/login" {
// 			c.Next()
// 			fmt.Println("sss")
// 		} else {
// 			h := AuthHeader{}
// 			if err := c.ShouldBindHeader(&h); err != nil {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthorized",
// 				})
// 				c.Abort()
// 			}

// 			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer", "", -1)
// 			fmt.Println("tokenString: ", tokenString)
// 			if h.AuthorizationHeader == "123456" {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthorized",
// 				})
// 				c.Abort()
// 				return
// 			}

// 			token, err := ParseToken(tokenString)
// 			if err != nil {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthorized",
// 				})
// 				c.Abort()
// 				return
// 			}
// 			fmt.Println("token: ", token)
// 			if token["iss"] == ApplicationName {
// 				c.Next()
// 			} else {
// 				c.JSON(http.StatusUnauthorized, gin.H{
// 					"message": "Unauthorized",
// 				})
// 				c.Abort()
// 				return
// 			}
// 		}
// 	}
// }

// func ParseToken(tokenString string) (jwt.MapClaims, error) {
// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("signin method invalid")
// 		} else if method != JwtSinginMethod {
// 			return nil, fmt.Errorf("signin method invalid")
// 		}
// 		return JwtSignatureKey, nil
// 	})
// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok || !token.Valid {
// 		return nil, err
// 	}
// 	return claims, nil
// }
