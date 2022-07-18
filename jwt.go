package jwt_middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Secret           string `json:"secret,omitempty"`
	AllowedRoles     string `json:"allowedRoles,omitempty"`
	PathsToBeChecked string `json:"pathsToBeChecked,omitempty"`
	AuthHeader       string `json:"authHeader,omitempty"`
	HeaderPrefix     string `json:"headerPrefix,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next             http.Handler
	name             string
	secret           string
	allowedRoles     []string
	pathsToBeChecked []string
	authHeader       string
	headerPrefix     string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Secret) == 0 {
		config.Secret = "SECRET"
	}
	if len(config.AllowedRoles) == 0 {
		config.AllowedRoles = "super,admin,staff"
	}
	if len(config.PathsToBeChecked) == 0 {
		config.PathsToBeChecked = "/static/document/, /static/file/, /static/staff/"
	}
	if len(config.AuthHeader) == 0 {
		config.AuthHeader = "Authorization"
	}
	if len(config.HeaderPrefix) == 0 {
		config.HeaderPrefix = "Bearer"
	}

	return &JWT{
		next:             next,
		name:             name,
		secret:           config.Secret,
		allowedRoles:     strings.Split(config.AllowedRoles, ","),
		pathsToBeChecked: strings.Split(config.PathsToBeChecked, ","),
		authHeader:       config.AuthHeader,
		headerPrefix:     config.HeaderPrefix,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(j.authHeader)

	// a helper function to check if the current path is in the scope of paths to be checked
	pathShouldBeChecked := func() bool {
		path := req.URL.Path
		for _, p := range j.pathsToBeChecked {
			if strings.Contains(path, p) {
				return true
			}
		}
		return false
	}

	if !pathShouldBeChecked() {
		j.next.ServeHTTP(res, req)
	}

	if len(headerToken) == 0 {
		http.Error(res, "Request error", http.StatusUnauthorized)
		return
	}

	token, err := getRawToken(headerToken, j.headerPrefix)
	if err != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	_, _, ok := VerifyToken(token, j.secret, j.allowedRoles)
	if ok {
		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
}

// ~ custom claims struct
type CustomClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Email    string `json:"email"`
	Avatar   string `json:"avatar"`
	Role     string `json:"role"`
}

// * a helper func to check the validity of the token
// @params: tokenString a string, the token
// @params: audience a string, the type of token including "activationToken", "accessToken", or others
// @params: allowedRoles an []string, who the token is being authorized to
func VerifyToken(tokenString, accessPublicKey string, allowedRoles []string) (*jwt.Token, *CustomClaims, bool) {
	//  ~ parsing token string
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := jwt.ParseEdPublicKeyFromPEM([]byte(accessPublicKey))
		if err != nil {
			return nil, errors.New("failed to parse ACCESS key")
		}

		// ~ verify the ed25519 token
		parts := strings.Split(tokenString, ".")
		if err = jwt.GetSigningMethod("EdDSA").Verify(strings.Join(parts[0:2], "."), parts[2], publicKey); err != nil {
			return nil, err
		}
		return publicKey, nil
	})
	// ? if parse token returns err then the token isn't a valid one
	if err != nil {
		ver, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(ver.Inner, errors.New("token has expired")) {
			return nil, nil, false
		}
		return nil, nil, false
	}
	// ~ parse the claims
	claims, ok := token.Claims.(*CustomClaims)

	// ? check if both token and claims are valid
	if token.Valid && ok && validateClaims(claims) {
		// ? only the role in claims matches allowed roles, we return the token and claims
		for _, v := range allowedRoles {
			if v == claims.Role {
				return token, claims, true
			}
		}
	}

	// ? if the token or claims aren't valid
	// fmt.Println(claims, ok, token.Valid)
	return nil, nil, false
}

// * helper function to validate claims by its time values
func validateClaims(claims *CustomClaims) bool {
	if claims.VerifyAudience("access_token", true) && claims.VerifyIssuer("uparis.org", true) && claims.VerifyExpiresAt(time.Now().UTC(), true) && claims.VerifyIssuedAt(time.Now().UTC(), true) && claims.VerifyNotBefore(time.Now().UTC(), true) {
		return true
	}
	fmt.Println("error on validating claims")
	return false
}

// getRawToken Takes the request header string, strips prefix and whitespaces and returns a raw token string
func getRawToken(reqHeader string, prefix string) (tokenString string, err error) {
	tokenString = strings.TrimPrefix(reqHeader, prefix)
	tokenString = strings.TrimSpace(tokenString)

	if tokenString == "" {
		return tokenString, errors.New("parse raw token failed")
	}
	return tokenString, nil
}
