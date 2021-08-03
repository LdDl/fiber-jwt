package jwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// FiberJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type FiberJWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on login info.
	// Must return user data as user identifier, it will be stored in Claim Array. Required.
	// Check error (e) to determine the appropriate error message.
	Authenticator func(c *fiber.Ctx) (interface{}, error)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(data interface{}, c *fiber.Ctx) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(data interface{}) MapClaims

	// User can define own Unauthorized func.
	Unauthorized func(*fiber.Ctx, int, string) error

	// User can define own LoginResponse func.
	LoginResponse func(*fiber.Ctx, int, string, time.Time) error

	// User can define own LogoutResponse func.
	LogoutResponse func(*fiber.Ctx, int) error

	// User can define own RefreshResponse func.
	RefreshResponse func(*fiber.Ctx, int, string, time.Time) error

	// Set the identity handler function
	IdentityHandler func(*fiber.Ctx) interface{}

	// Set the identity key
	IdentityKey string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
	TimeFunc func() time.Time

	// HTTP Status messages for when something in the JWT middleware fails.
	// Check error (e) to determine the appropriate error message.
	HTTPStatusMessageFunc func(e error, c *fiber.Ctx) string

	// Private key file for asymmetric algorithms
	PrivKeyFile string

	// Private Key bytes for asymmetric algorithms
	//
	// Note: PrivKeyFile takes precedence over PrivKeyBytes if both are set
	PrivKeyBytes []byte

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// Public key bytes for asymmetric algorithms.
	//
	// Note: PubKeyFile takes precedence over PubKeyBytes if both are set
	PubKeyBytes []byte

	// Private key
	privKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	// Optionally return the token as a cookie
	SendCookie bool

	// Duration that a cookie is valid. Optional, by default equals to Timeout value.
	CookieMaxAge time.Duration

	// Allow insecure cookies for development over http
	SecureCookie bool

	// Allow cookies to be accessed client side for development
	CookieHTTPOnly bool

	// Allow cookie domain change for development
	CookieDomain string

	// SendAuthorization allow return authorization header for every request
	SendAuthorization bool

	// Disable abort() of context.
	DisabledAbort bool

	// CookieName allow cookie name change for development
	CookieName string
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"
)

// New for check error with FiberJWTMiddleware
func New(m *FiberJWTMiddleware) (*FiberJWTMiddleware, error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}

	return m, nil
}

func (mw *FiberJWTMiddleware) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}
	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (mw *FiberJWTMiddleware) privateKey() error {
	keyData := []byte{}
	if mw.PrivKeyFile == "" {
		keyData = mw.PrivKeyBytes
	} else {
		filecontent, err := ioutil.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *FiberJWTMiddleware) publicKey() error {
	keyData := []byte{}
	if mw.PubKeyFile == "" {
		keyData = mw.PubKeyBytes
	} else {
		filecontent, err := ioutil.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *FiberJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initialize jwt configs.
func (mw *FiberJWTMiddleware) MiddlewareInit() error {

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c *fiber.Ctx) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *fiber.Ctx, code int, message string) error {
			return c.Status(code).JSON(fiber.Map{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) error {
			return c.Status(http.StatusOK).JSON(fiber.Map{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(c *fiber.Ctx, code int) error {
			return c.Status(http.StatusOK).JSON(fiber.Map{
				"code": http.StatusOK,
			})
		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) error {
			return c.Status(http.StatusOK).JSON(fiber.Map{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(c *fiber.Ctx) interface{} {
			claims := ExtractClaims(c)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, c *fiber.Ctx) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		mw.Realm = "fiber jwt"
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

// MiddlewareFunc makes FiberJWTMiddleware implement the Middleware interface.
func (mw *FiberJWTMiddleware) MiddlewareFunc() func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		return mw.middlewareImpl(c)
	}
}

func (mw *FiberJWTMiddleware) middlewareImpl(c *fiber.Ctx) error {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	}

	if claims["exp"] == nil {
		return mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, c))
	}

	if _, ok := claims["exp"].(float64); !ok {
		return mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, c))
	}

	if int64(claims["exp"].(float64)) < mw.TimeFunc().Unix() {
		return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
	}

	c.Context().SetUserValue("JWT_PAYLOAD", claims)
	// c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(c)

	if identity != nil {
		c.Context().SetUserValue(mw.IdentityKey, identity)
		// c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, c) {
		return mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
	}

	return c.Next()
}

// GetClaimsFromJWT get claims from JWT token
func (mw *FiberJWTMiddleware) GetClaimsFromJWT(c *fiber.Ctx) (MapClaims, error) {
	token, err := mw.ParseToken(c)

	if err != nil {
		return nil, err
	}

	if mw.SendAuthorization {
		v := c.Context().UserValue("JWT_TOKEN")
		if v != nil {
			c.Context().Request.Header.Set("Authorization", mw.TokenHeadName+" "+v.(string))
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *FiberJWTMiddleware) LoginHandler(c *fiber.Ctx) error {
	if mw.Authenticator == nil {
		return mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
	}

	data, err := mw.Authenticator(c)

	if err != nil {
		return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)

	if err != nil {
		return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
	}

	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())

		cookies := &fiber.Cookie{
			Name:     mw.CookieName,
			Value:    tokenString,
			Path:     "/",
			Expires:  time.Now().Add(time.Duration(maxage) * time.Second),
			Domain:   mw.CookieDomain,
			Secure:   mw.SecureCookie,
			HTTPOnly: mw.CookieHTTPOnly,
		}
		c.Cookie(cookies)
	}

	return mw.LoginResponse(c, http.StatusOK, tokenString, expire)
}

// LogoutHandler can be used by clients to remove the jwt cookie (if set)
func (mw *FiberJWTMiddleware) LogoutHandler(c *fiber.Ctx) error {
	// delete auth cookie
	if mw.SendCookie {

		cookies := &fiber.Cookie{
			Name:     mw.CookieName,
			Value:    "",
			Path:     "/",
			Expires:  time.Now().Add(-1 * time.Second),
			Domain:   mw.CookieDomain,
			Secure:   mw.SecureCookie,
			HTTPOnly: mw.CookieHTTPOnly,
		}
		c.Cookie(cookies)
	}

	return mw.LogoutResponse(c, http.StatusOK)
}

func (mw *FiberJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the FiberJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *FiberJWTMiddleware) RefreshHandler(c *fiber.Ctx) error {
	tokenString, expire, err := mw.RefreshToken(c)
	if err != nil {
		return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	}

	return mw.RefreshResponse(c, http.StatusOK, tokenString, expire)
}

// RefreshToken refresh token and check if token is expired
func (mw *FiberJWTMiddleware) RefreshToken(c *fiber.Ctx) (string, time.Time, error) {
	claims, err := mw.CheckIfTokenExpire(c)
	if err != nil {
		return "", time.Now(), err
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(newToken)

	if err != nil {
		return "", time.Now(), err
	}

	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - time.Now().Unix())

		cookies := &fiber.Cookie{
			Name:     mw.CookieName,
			Value:    tokenString,
			Path:     "/",
			Expires:  time.Now().Add(time.Duration(maxage) * time.Second),
			Domain:   mw.CookieDomain,
			Secure:   mw.SecureCookie,
			HTTPOnly: mw.CookieHTTPOnly,
		}
		c.Cookie(cookies)
	}

	return tokenString, expire, nil
}

// CheckIfTokenExpire check if token expire
func (mw *FiberJWTMiddleware) CheckIfTokenExpire(c *fiber.Ctx) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c)

	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// TokenGenerator method that clients can use to get a jwt token.
func (mw *FiberJWTMiddleware) TokenGenerator(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().UTC().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *FiberJWTMiddleware) jwtFromHeader(c *fiber.Ctx, key string) (string, error) {
	authHeader := c.Context().Request.Header.Peek(key)

	if string(authHeader) == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(string(authHeader), " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *FiberJWTMiddleware) jwtFromQuery(c *fiber.Ctx, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *FiberJWTMiddleware) jwtFromCookie(c *fiber.Ctx, key string) (string, error) {

	cookie := c.Cookies(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *FiberJWTMiddleware) jwtFromParam(c *fiber.Ctx, key string) (string, error) {
	token := c.Context().UserValue(key)
	tokenStr := ""
	if token != nil {
		switch token.(type) {
		case string:
			tokenStr = token.(string)
			break
		default:
			break
		}
	} else {
		return "", ErrEmptyParamToken
	}

	if tokenStr == "" {
		return "", ErrEmptyParamToken
	}

	return tokenStr, nil
}

// ParseToken parse jwt token from gin context
func (mw *FiberJWTMiddleware) ParseToken(c *fiber.Ctx) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "query":
			token, err = mw.jwtFromQuery(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		case "param":
			token, err = mw.jwtFromParam(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// save token string if vaild
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	})
}

// ParseTokenString parse jwt token string
func (mw *FiberJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		return mw.Key, nil
	})
}

func (mw *FiberJWTMiddleware) unauthorized(c *fiber.Ctx, code int, message string) error {
	c.Context().Request.Header.Set("WWW-Authenticate", "JWT realm="+mw.Realm)
	if !mw.DisabledAbort {
		// @todo abort?
	}
	return mw.Unauthorized(c, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *fiber.Ctx) MapClaims {
	claims := c.Context().UserValue("JWT_PAYLOAD")
	if claims == nil {
		return make(MapClaims)
	}
	return claims.(MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
func GetToken(c *fiber.Ctx) string {
	token := c.Context().UserValue("JWT_TOKEN")
	if token == nil {
		return ""
	}
	return token.(string)
}
