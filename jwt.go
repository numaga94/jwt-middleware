package jwt_middleware

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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
	Issuer    string    `json:"iss,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Audience  []string  `json:"aud,omitempty"`
	ExpiresAt time.Time `json:"exp,omitempty"`
	NotBefore time.Time `json:"nbf,omitempty"`
	IssuedAt  time.Time `json:"iat,omitempty"`
	ID        string    `json:"jti,omitempty"`
	Username  string    `json:"username,omitempty"`
	Email     string    `json:"email,omitempty"`
	Avatar    string    `json:"avatar,omitempty"`
	Role      string    `json:"role,omitempty"`
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
	result := strings.TrimSpace(strings.ToLower(expected)) == strings.TrimSpace(strings.ToLower(c.Issuer))
	fmt.Printf("issuer:%v, expected:%v, result:%v", c.Issuer, expected, result)
	return result
}

func (c *Claims) VerifyExpiresAt() bool {
	return c.ExpiresAt.After(time.Now())
}

func (c *Claims) VerifyIssuedAt() bool {
	return c.IssuedAt.Before(time.Now())
}

func (c *Claims) VerifyNotBefore() bool {
	return c.NotBefore.Before(time.Now())
}

func (c *Claims) VerifyRole(allowedRoles []string) bool {
	for _, v := range allowedRoles {
		if v == c.Role {
			return true
		}
	}
	fmt.Println("user role is out of the scope of authorized roles")
	return false
}

func VerifyToken(tokenString, accessPublicKey string, allowedRoles []string) error {
	//  ~ parse EdPublic key from PEM
	publicKey, err := ParseEdPublicKeyFromPEM([]byte(accessPublicKey))
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	// ~ verify the ed25519 token
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return errors.New("parts not correct")
	}
	if err := Verify(strings.Join(parts[0:2], "."), parts[2], publicKey); err != nil {
		fmt.Println(err.Error())
		return err
	}

	// ~ parse the claims
	claims, err := ParseClaims(parts[1])
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	// ? check if both token and claims are valid
	if err := validateClaims(claims, allowedRoles); err != nil {
		fmt.Println(err.Error())
		return err
	}

	return nil
}

// * helper function to validate claims by its time values
func validateClaims(claims Claims, allowedRoles []string) error {
	audValid := claims.VerifyAudience("access_token")
	issValid := claims.VerifyIssuer("uparis.org")
	expAtValid := claims.VerifyExpiresAt()
	issAtValid := claims.VerifyIssuedAt()
	nbfAtValid := claims.VerifyNotBefore()
	roleValid := claims.VerifyRole(allowedRoles)
	if audValid && issValid && expAtValid && issAtValid && nbfAtValid && roleValid {
		return nil
	}
	return fmt.Errorf("aud:%v, iss:%v, expAt:%v, issAt:%v, nbfAt:%v", audValid, issValid, expAtValid, issAtValid, nbfAtValid)
}

// getRawToken Takes the request header string, strips prefix and whitespaces and returns a raw token string
func getRawToken(reqHeader string, prefix string) (tokenString string, err error) {
	if !strings.Contains(reqHeader, prefix) {
		return tokenString, errors.New("bearer prefix not found in request header")
	}
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
		fmt.Println("invalid key type")
		return errors.New("invalid key type")
	}

	// if len(ed25519Key) != ed25519.PublicKeySize {
	// 	fmt.Println("invalid key")
	// 	return errors.New("invalid key")
	// }

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		fmt.Println(err.Error())
		return err
	}

	fmt.Println("verify the signature")

	// Verify the signature
	if !ed25519.Verify(ed25519Key, []byte(signingString), sig) {
		fmt.Println("ed25519 verification failed")
		return errors.New("ed25519 verification failed")
	}

	fmt.Println("verified")

	return nil
}

// ParseEdPublicKeyFromPEM parses a PEM-encoded Edwards curve public key
func ParseEdPublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		fmt.Println("key must be PEM encoded")
		return nil, errors.New("key must be PEM encoded")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	var pkey ed25519.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
		fmt.Println("key is not a valid Ed25519 public key")
		return nil, errors.New("key is not a valid Ed25519 public key")
	}

	return pkey, nil
}

func ParseClaims(seg string) (claims Claims, err error) {
	segByte, err := DecodeSegment(seg)
	if err != nil {
		return claims, errors.New("decode segment failed")
	}

	var decodedJson map[string]interface{}
	if err := json.NewDecoder(bytes.NewBuffer(segByte)).Decode(&decodedJson); err != nil {
		return claims, err
	}

	fmt.Println(decodedJson)

	for k, v := range decodedJson {
		switch k {
		case "aud":
			s := fmt.Sprintf("%v", v)
			s = strings.TrimLeft(s, "[")
			s = strings.TrimRight(s, "]")
			claims.Audience = []string{s}

		case "avatar":
			claims.Avatar = fmt.Sprintf("%v", v)

		case "email":
			claims.Email = fmt.Sprintf("%v", v)

		case "exp":
			vString := fmt.Sprintf("%v", v)
			vString = strings.Split(vString, "e")[0]
			vString = strings.ReplaceAll(vString, ".", "")
			vString = strings.TrimSpace(vString)
			if i, err := strconv.ParseInt(vString, 10, 64); err != nil {
				claims.ExpiresAt = time.Now().Add(-time.Minute)
			} else {
				claims.ExpiresAt = time.Unix(i, 0)
			}

		case "iat":
			vString := fmt.Sprintf("%v", v)
			vString = strings.Split(vString, "e")[0]
			vString = strings.ReplaceAll(vString, ".", "")
			vString = strings.TrimSpace(vString)
			if i, err := strconv.ParseInt(vString, 10, 64); err != nil {
				claims.IssuedAt = time.Now().Add(-time.Minute)
			} else {
				claims.IssuedAt = time.Unix(i, 0)
			}

		case "iss":
			claims.Issuer = fmt.Sprintf("%v", v)

		case "jti":
			claims.ID = fmt.Sprintf("%v", v)

		case "nbf":
			vString := fmt.Sprintf("%v", v)
			vString = strings.Split(vString, "e")[0]
			vString = strings.ReplaceAll(vString, ".", "")
			vString = strings.TrimSpace(vString)
			if i, err := strconv.ParseInt(vString, 10, 64); err != nil {
				claims.NotBefore = time.Now().Add(-time.Minute)
			} else {
				claims.NotBefore = time.Unix(i, 0)
			}

		case "role":
			claims.Role = fmt.Sprintf("%v", v)

		case "sub":
			claims.Subject = fmt.Sprintf("%v", v)

		case "username":
			claims.Username = fmt.Sprintf("%v", v)

		default:
			return
		}
	}
	fmt.Printf("expAt:%v, issAt:%v, nbfAt:%v", claims.ExpiresAt, claims.IssuedAt, claims.NotBefore)
	return claims, nil
}

// DecodeSegment decodes a JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
