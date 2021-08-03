package jwt

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(ctx *fiber.Ctx) (interface{}, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password
		if userID == "admin" && password == "admin" {
			return userID, nil
		}
		return userID, ErrFailedAuthentication
	}
)

func makeTokenString(SigningAlgorithm string, username string) string {
	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if SigningAlgorithm == "RS256" {
		keyData, _ := ioutil.ReadFile("test_data/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func TestMissingKey(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	assert.Error(t, err)
	assert.Equal(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "nonexisting",
	})
	assert.Error(t, err)
	assert.Equal(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/jwtRS256.key",
		PubKeyFile:       "nonexisting",
	})
	assert.Error(t, err)
	assert.Equal(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/invalidprivkey.key",
		PubKeyFile:       "test_data/jwtRS256.key.pub",
	})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPrivKeyBytes(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     []byte("Invalid_Private_Key"),
		PubKeyFile:       "test_data/jwtRS256.key.pub",
	})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/jwtRS256.key",
		PubKeyFile:       "test_data/invalidpubkey.key",
	})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestInvalidPubKeyBytes(t *testing.T) {
	_, err := New(&FiberJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/jwtRS256.key",
		PubKeyBytes:      []byte("Invalid_Private_Key"),
	})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestMissingTimeOut(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	assert.Equal(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(ctx *fiber.Ctx) error {
	return ctx.Status(200).JSON(map[string]string{"text": "Hello World.", "token": GetToken(ctx)})
}

func fiberHandler(auth *FiberJWTMiddleware) *fiber.App {
	r := fiber.New()
	r.Post("/login", auth.LoginHandler)
	r.Post("/logout", auth.LogoutHandler)
	// test token in path
	r.Get("/g/:token/refresh_token", auth.RefreshHandler)
	group := r.Group("/auth")
	// Refresh time can be longer than token timeout
	group.Get("/refresh_token", auth.RefreshHandler)
	group.Use(auth.MiddlewareFunc())
	{
		group.Get("/hello", helloHandler)
	}
	return r
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	resp, err := handler.Test(
		httptest.NewRequest("POST", "/login", nil),
	)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message := gjson.Get(string(body), "message")
	assert.Equal(t, ErrMissingAuthenticatorFunc.Error(), message.String())
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
