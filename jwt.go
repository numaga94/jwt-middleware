package jwt_middleware

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"
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
	// a helper function to check if the current path is in the scope of paths to be checked
	path := req.URL.Path
	if !pathShouldBeChecked(path, j.pathsToBeChecked) {
		j.next.ServeHTTP(res, req)
	}

	headerToken := req.Header.Get(j.authHeader)

	if len(headerToken) == 0 {
		http.Error(res, "Request error", http.StatusUnauthorized)
		return
	}

	token, err := getRawToken(headerToken, j.headerPrefix)
	if err != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	if err := VerifyToken(token, j.secret, j.allowedRoles); err != nil {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	} else {
		j.next.ServeHTTP(res, req)
	}
}

func pathShouldBeChecked(path string, paths []string) bool {
	for _, p := range paths {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// ~ custom claims struct
type Claims struct {
	Issuer    string     `json:"iss,omitempty"`
	Subject   string     `json:"sub,omitempty"`
	Audience  []string   `json:"aud,omitempty"`
	ExpiresAt *time.Time `json:"exp,omitempty"`
	NotBefore *time.Time `json:"nbf,omitempty"`
	IssuedAt  *time.Time `json:"iat,omitempty"`
	ID        string     `json:"jti,omitempty"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Avatar    string     `json:"avatar"`
	Role      string     `json:"role"`
}

func (c *Claims) VerifyAudience(expected string) bool {
	for _, v := range c.Audience {
		if strings.TrimSpace(strings.ToLower(expected)) == strings.TrimSpace(strings.ToLower(v)) {
			return true
		}
	}
	return false
}

func (c *Claims) VerifyIssuer(expected string) bool {
	return strings.TrimSpace(strings.ToLower(expected)) == strings.TrimSpace(strings.ToLower(c.Issuer))
}

func (c *Claims) VerifyExpiresAt() bool {
	return c.ExpiresAt.After(time.Now())
}

func (c *Claims) VerifyIssuedAt() bool {
	return c.IssuedAt.After(time.Now())
}

func (c *Claims) VerifyNotBefore() bool {
	return c.NotBefore.After(time.Now())
}

func VerifyToken(tokenString, accessPublicKey string, allowedRoles []string) error {
	//  ~ parse EdPublic key from PEM
	publicKey, err := ParseEdPublicKeyFromPEM([]byte(accessPublicKey))
	if err != nil {
		return err
	}
	// ~ verify the ed25519 token
	parts := strings.Split(tokenString, ".")
	if err := Verify(strings.Join(parts[0:2], "."), parts[2], publicKey); err != nil {
		return err
	}

	// ~ parse the claims
	claims, err := ParseClaims(parts[1])
	if err != nil {
		return err
	}

	// ? check if both token and claims are valid
	if err := validateClaims(claims); err != nil {
		return err
	}

	// ? only the role in claims matches allowed roles, we return the token and claims
	for _, v := range allowedRoles {
		if v == claims.Role {
			return nil
		}
	}

	return errors.New("user roles is out of authorized scope")
}

// * helper function to validate claims by its time values
func validateClaims(claims Claims) error {
	if claims.VerifyAudience("access_token") && claims.VerifyIssuer("uparis.org") && claims.VerifyExpiresAt() && claims.VerifyIssuedAt() && claims.VerifyNotBefore() {
		return nil
	}
	return errors.New("claims not valid")
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

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ed25519.PublicKey
func Verify(signingString, signature string, key interface{}) error {
	var err error
	var ed25519Key ed25519.PublicKey
	var ok bool

	if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
		return errors.New("invalid key type")
	}

	if len(ed25519Key) != ed25519.PublicKeySize {
		return errors.New("invalid key")
	}

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Verify the signature
	if !ed25519.Verify(ed25519Key, []byte(signingString), sig) {
		return errors.New("ed25519 verification failed")
	}

	return nil
}

// ParseEdPublicKeyFromPEM parses a PEM-encoded Edwards curve public key
func ParseEdPublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("key must be PEM encoded")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey ed25519.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("key is not a valid Ed25519 public key")
	}

	return pkey, nil
}

func ParseClaims(seg string) (claims Claims, err error) {
	segByte, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return claims, errors.New("decode segment failed")
	}
	if err := json.Unmarshal(segByte, &claims); err != nil {
		return claims, errors.New("unmarshal json failed")
	}
	return claims, nil
}

// DecodeSegment decodes a JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
