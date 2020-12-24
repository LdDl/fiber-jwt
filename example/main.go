package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	jwt "github.com/LdDl/fiber-jwt/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	api := app.Group("/api")
	apiv001 := api.Group("/v0.0.1")

	database := Database{
		UserData{
			Name:        "user",
			Password:    "pass",
			Description: "simple user",
			Access:      "Authentication",
		},
		UserData{
			Name:        "user2",
			Password:    "pass",
			Description: "simple user2",
			Access:      "Banned",
		},
	}

	jwtBus := InitAuth(database)

	api.Post("/doauth", jwtBus.LoginHandler)

	apiv001.Get("/public", Public())

	apiv001.Use(jwtBus.MiddlewareFunc())
	apiv001.Get("/refresh_token", jwtBus.RefreshHandler)
	apiv001.Get("/secret_page", SecretPage())

	app.Listen(":8080")
}

type Data struct {
	Kek   int    `json:"x"`
	Memes string `json:"y"`
}

func Public() func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		return ctx.Status(200).JSON(map[string]string{"not": "secret"})
	}
}

func SecretPage() func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		return ctx.Status(200).JSON(map[string]string{"very": "secret"})
	}
}

type UserData struct {
	Name        string
	Password    string
	Description string
	Access      string
}

type Database []UserData

func (db Database) CheckUser(login string) (UserData, error) {
	for i := range db {
		if db[i].Name == login {
			return db[i], nil
		}
	}
	return UserData{}, fmt.Errorf("No user")
}

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func InitAuth(db Database) *jwt.FiberJWTMiddleware {
	identityKey := "login"
	authMiddleware, err := jwt.New(&jwt.FiberJWTMiddleware{
		Realm:            "fiber",
		Key:              []byte("fiber123"),
		Timeout:          time.Hour * 24,
		MaxRefresh:       time.Hour * 24,
		IdentityKey:      identityKey,
		SigningAlgorithm: "HS256",
		PayloadFunc: func(userId interface{}) jwt.MapClaims {
			user, _ := db.CheckUser(userId.(string))
			return jwt.MapClaims{
				"login": userId.(string),
				"desc":  user.Description,
			}
		},
		IdentityHandler: func(c *fiber.Ctx) interface{} {
			claims := jwt.ExtractClaims(c)
			return &UserData{
				Name:        claims["login"].(string),
				Description: claims["desc"].(string),
			}
		},
		Authenticator: func(ctx *fiber.Ctx) (interface{}, error) {
			loginVals := login{}
			bodyBytes := ctx.Context().PostBody()
			if err := json.Unmarshal(bodyBytes, &loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			user, err := db.CheckUser(userID)
			if err != nil {
				return userID, jwt.ErrFailedAuthentication
			}
			if password == user.Password && user.Access == "Authentication" {
				return userID, jwt.ErrForbidden
			}
			return userID, jwt.ErrFailedAuthentication
		},
		Authorizator: func(userId interface{}, ctx *fiber.Ctx) bool {
			user, err := db.CheckUser(userId.(*UserData).Name)
			if err != nil {
				return false
			}
			if user.Access == "Authentication" {
				return true
			}
			return false
		},
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			if message == jwt.ErrFailedAuthentication.Error() {
				return ctx.Status(401).JSON(fiber.Map{"Error": string(ctx.Context().URI().Path()) + ";Unauthorized"})
			}
			return ctx.Status(403).JSON(fiber.Map{"Error": string(ctx.Context().URI().Path()) + message})
		},
		TokenLookup:   "header: Authorization, query: token, cookie: token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
	if err != nil {
		log.Println("Can not init auth")
		return nil
	}
	return authMiddleware
}
