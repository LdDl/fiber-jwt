package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
				"message": "login successfully!",
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
	assert.Equal(t, "login successfully!", message.String())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestParseToken(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Test 1234")
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS384", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestParseTokenRS256(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/jwtRS256.key",
		PubKeyFile:       "test_data/jwtRS256.key.pub",
		Authenticator:    defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Test 1234")
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS384", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("RS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRefreshHandler(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Test 1234")
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS384", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRefreshHandlerRS256(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "test_data/jwtRS256.key",
		PubKeyFile:       "test_data/jwtRS256.key.pub",
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(ctx *fiber.Ctx, code int, token string, tm time.Time) error {
			return ctx.Status(http.StatusOK).JSON(fiber.Map{
				"code":    http.StatusOK,
				"token":   token,
				"expire":  tm.Format(time.RFC3339),
				"message": "refresh successfully!",
			})
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Test 1234")
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("RS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message := gjson.Get(string(body), "message")
	assert.Equal(t, "refresh successfully!", message.String())
}

func TestExpiredTokenWithinMaxRefreshOnRefreshHandler(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    2 * time.Hour,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	claims["orig_iat"] = time.Now().Add(-time.Hour).Unix()
	tokenString, err := token.SignedString(key)
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestExpiredTokenOnRefreshHandler(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = 0
	tokenString, err := token.SignedString(key)
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestTokenExpire(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    -time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestExpiredField(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["orig_iat"] = 0
	tokenString, err := token.SignedString(key)
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err := handler.Test(req)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message := gjson.Get(string(body), "message")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, ErrMissingExpField.Error(), message.String())
	// wrong format
	claims["exp"] = "test"
	tokenString, err = token.SignedString(key)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err = handler.Test(req)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	message = gjson.Get(string(body), "message")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, strings.ToLower(ErrExpiredToken.Error()), strings.ToLower(message.String()))
}

func TestExpiredTokenOnAuth(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizator: func(data interface{}, ctx *fiber.Ctx) bool {
			return data.(string) == "admin"
		},
		TimeFunc: func() time.Time {
			return time.Now().AddDate(0, 0, 1)
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthorizator(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Authorizator: func(data interface{}, ctx *fiber.Ctx) bool {
			return data.(string) == "admin"
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "test"))
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestUnauthorized(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer 1234")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogout(t *testing.T) {
	cookieName := "jwt"
	cookieDomain := "example.com"
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		SendCookie:    true,
		CookieName:    cookieName,
		CookieDomain:  cookieDomain,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("POST", "/logout", nil)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	respCookie := resp.Header.Get("Set-Cookie")
	assert.Equal(t, fmt.Sprintf("%s=; domain=%s; path=/; SameSite=Lax", cookieName, cookieDomain), respCookie)
}

func TestClaimsDuringAuthorization(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(MapClaims); ok {
				return v
			}
			if reflect.TypeOf(data).String() != "string" {
				return MapClaims{}
			}
			var testkey string
			switch data.(string) {
			case "admin":
				testkey = "1234"
			case "test":
				testkey = "5678"
			case "Guest":
				testkey = ""
			}
			// Set custom claim, to be checked in Authorizator method
			return MapClaims{"identity": data.(string), "testkey": testkey, "exp": 0}
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
			if userID == "test" && password == "test" {
				return userID, nil
			}
			return "Guest", ErrFailedAuthentication
		},
		Authorizator: func(user interface{}, ctx *fiber.Ctx) bool {
			jwtClaims := ExtractClaims(ctx)
			if jwtClaims["identity"] == "administrator" {
				return true
			}
			if jwtClaims["testkey"] == "1234" && jwtClaims["identity"] == "admin" {
				return true
			}
			if jwtClaims["testkey"] == "5678" && jwtClaims["identity"] == "test" {
				return true
			}
			return false
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "administrator",
	})
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	reqBody, err := json.Marshal(fiber.Map{
		"username": "admin",
		"password": "admin",
	})
	assert.NoError(t, err)
	resp, err = handler.Test(
		httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody)),
	)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	reqBody, err = json.Marshal(fiber.Map{
		"username": "test",
		"password": "test",
	})
	assert.NoError(t, err)
	resp, err = handler.Test(
		httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody)),
	)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	messageToken := gjson.Get(string(body), "token")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+messageToken.String())
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEmptyClaims(t *testing.T) {
	jwtClaims := MapClaims{}
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(ctx *fiber.Ctx) (interface{}, error) {
			loginVals := Login{}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == "admin" && password == "admin" {
				return "", nil
			}
			if userID == "test" && password == "test" {
				return "Administrator", nil
			}
			return userID, ErrFailedAuthentication
		},
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			assert.Empty(t, ExtractClaims(ctx))
			assert.Empty(t, map[string]interface{}{})
			return ctx.Status(code).SendString(message)
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer 1234")
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, jwtClaims)
}

func TestCheckTokenString(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       1 * time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(MapClaims); ok {
				return v
			}
			return nil
		},
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	token, err := authMiddleware.ParseTokenString(userToken)
	assert.NoError(t, err)
	claims := ExtractClaimsFromToken(token)
	assert.Equal(t, "admin", claims["identity"])
	// Make a delay
	time.Sleep(2 * time.Second)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_, err = authMiddleware.ParseTokenString(userToken)
	assert.Error(t, err)
	assert.Equal(t, MapClaims{}, ExtractClaimsFromToken(nil))
}

func TestTokenFromQueryString(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
		TokenLookup: "query:token",
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/refresh_token?token="+userToken, nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTokenFromParamPath(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
		TokenLookup: "param:token",
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/g/"+userToken+"/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTokenFromCookieString(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx *fiber.Ctx, code int, message string) error {
			return ctx.Status(code).SendString(message)
		},
		TokenLookup: "cookie:token",
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	userToken, _, err := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})
	assert.NoError(t, err)
	req := httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	messageToken := gjson.Get(string(body), "token")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "", messageToken.String())
	req = httptest.NewRequest("GET", "/auth/refresh_token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: userToken,
	})
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: userToken,
	})
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	body, err = ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	messageToken = gjson.Get(string(body), "token")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, userToken, messageToken.String())
}

func TestDefineTokenHeadName(t *testing.T) {
	authMiddleware, err := New(&FiberJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)
	handler := fiberHandler(authMiddleware)
	req := httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString("HS256", "admin"))
	resp, err := handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	req = httptest.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "JWTTOKEN "+makeTokenString("HS256", "admin"))
	resp, err = handler.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
