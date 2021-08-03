package jwt

import (
	"bytes"
	"encoding/json"
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

func TestLoginHandler(t *testing.T) {
	cookieName := "jwt"
	cookieDomain := "example.com"
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data interface{}) MapClaims {
			// Set custom claim, to be checked in Authorizator method
			return MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(ctx *fiber.Ctx) (interface{}, error) {
			loginVals := Login{}
			bodyBytes := ctx.Context().PostBody()
			if err := json.Unmarshal(bodyBytes, &loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			if loginVals.Username == "" || loginVals.Password == "" {
				return "", ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == "admin" && password == "admin" {
				return userID, nil
			}
			return "", ErrFailedAuthentication
		},
		Authorizator: func(user interface{}, c *fiber.Ctx) bool {
			return true
		},
		LoginResponse: func(ctx *fiber.Ctx, code int, token string, tm time.Time) error {
			return ctx.Status(http.StatusOK).JSON(fiber.Map{
				"code":    http.StatusOK,
				"token":   token,
				"expire":  tm.Format(time.RFC3339),
				"message": "login successfully",
			})
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)

	reqBody, err := json.Marshal(fiber.Map{
		"username": "admin",
	})
	assert.NoError(t, err)
	resp, err := handler.Test(
		httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody)),
	)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message := gjson.Get(string(body), "message")
	assert.Equal(t, ErrMissingLoginValues.Error(), message.String())
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	reqBody, err = json.Marshal(fiber.Map{
		"username": "admin",
		"password": "test",
	})
	assert.NoError(t, err)
	resp, err = handler.Test(
		httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody)),
	)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message = gjson.Get(string(body), "message")
	assert.Equal(t, ErrFailedAuthentication.Error(), message.String())
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	reqBody, err = json.Marshal(fiber.Map{
		"username": "admin",
		"password": "admin",
	})
	assert.NoError(t, err)
	resp, err = handler.Test(
		httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody)),
	)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message = gjson.Get(string(body), "message")
	assert.Equal(t, "login successfully", message.String())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestParseToken(t *testing.T) {
	authMiddleware, _ := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "")
	resp, err := handler.Test(
		req,
	)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Test 1234")
	resp, err = handler.Test(
		req,
	)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS384", "admin"))
	resp, err = handler.Test(
		req,
	)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err = handler.Test(
		req,
	)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
