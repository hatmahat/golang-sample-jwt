package config

import (
	"time"

	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
)

type TokenConfig struct {
	ApplicationName     string
	JwtSigningMethod    *jwt.SigningMethodHMAC
	JwtSignatureKey     string
	AccessTokenLifeTime time.Duration
	Client              *redis.Client
}

type Config struct {
	TokenConfig
}

func (c Config) readConfig() Config {
	c.TokenConfig = TokenConfig{
		ApplicationName:     "ENIGMA",
		JwtSigningMethod:    jwt.SigningMethodHS256,
		JwtSignatureKey:     "3N!GM4",
		AccessTokenLifeTime: 60 * time.Second,
	}
	return c
}

func NewConfig() Config {
	cfg := Config{}
	return cfg.readConfig()
}
