package main

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/byebyebymyai/jose-api/entity/jwk"
)

type TokenService interface {
	MakeTokenStrings(claims jwt.MapClaims) ([]string, error)
}

type KeyPairService interface {
	GetPublicKeyPairSet() (jwk.JWKSet, error)
}

type defaultTokenService struct {
	Jwks jwk.JWKSet
}

// MakeTokenStrings implements TokenService.
func (s defaultTokenService) MakeTokenStrings(claims jwt.MapClaims) ([]string, error) {
	tokenStrings := make([]string, 0, len(s.Jwks.Keys))
	for _, v := range s.Jwks.Keys {

		var iss string
		if claims["iss"] != nil {
			iss = claims["iss"].(string)
		}

		var sub string
		if claims["id"] != nil {
			sub = claims["id"].(string)
		} else if claims["sub"] != nil {
			sub = claims["sub"].(string)
		}

		var aud jwt.ClaimStrings
		if claims["aud"] != nil {
			aud, _ = claims.GetAudience()
		}

		var exp *jwt.NumericDate
		if claims["exp"] != nil {
			exp = jwt.NewNumericDate(time.Now().Add(time.Duration(claims["exp"].(float64)) * time.Second))
		}

		var jti string
		if claims["jti"] != nil {
			jti = claims["jti"].(string)
		} else {
			jti = uuid.New().String()
		}

		registeredClaimsStruct := &jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  aud,
			ExpiresAt: exp,
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		}

		var registeredClaims map[string]interface{}
		registeredClaimsJson, _ := json.Marshal(registeredClaimsStruct)
		json.Unmarshal(registeredClaimsJson, &registeredClaims)

		tokenString, err := makeTokenString(v, mergeMaps(claims, registeredClaims))
		if err != nil {
			return nil, err
		}

		tokenStrings = append(tokenStrings, tokenString)
	}
	return tokenStrings, nil
}

func makeTokenString(Jwk jwk.JWK, claims jwt.MapClaims) (string, error) {
	token, err := makeToken(Jwk)
	if err != nil {
		return "", err
	}

	token.Claims = claims
	token.Header["kid"] = Jwk.KID

	tokenString, err := token.SignedString(Jwk.PrivateKey())
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func makeToken(Jwk jwk.JWK) (*jwt.Token, error) {
	switch Jwk.ALG {
	case jwk.AlgHS256:
		return jwt.New(jwt.SigningMethodHS256), nil
	case jwk.AlgHS384:
		return jwt.New(jwt.SigningMethodHS384), nil
	case jwk.AlgHS512:
		return jwt.New(jwt.SigningMethodHS512), nil

	case jwk.AlgRS256:
		return jwt.New(jwt.SigningMethodRS256), nil
	case jwk.AlgRS384:
		return jwt.New(jwt.SigningMethodRS384), nil
	case jwk.AlgRS512:
		return jwt.New(jwt.SigningMethodRS512), nil

	case jwk.AlgES256:
		return jwt.New(jwt.SigningMethodES256), nil
	case jwk.AlgES384:
		return jwt.New(jwt.SigningMethodES384), nil
	case jwk.AlgES512:
		return jwt.New(jwt.SigningMethodES512), nil

	case jwk.AlgPS256:
		return jwt.New(jwt.SigningMethodPS256), nil
	case jwk.AlgPS384:
		return jwt.New(jwt.SigningMethodPS384), nil
	case jwk.AlgPS512:
		return jwt.New(jwt.SigningMethodPS512), nil

	default:
		return nil, jwk.ErrUnsupportedKey
	}
}

func mergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

type defaultKeyPairService struct {
	Jwks jwk.JWKSet
}

// MakePublicKeyPairSet implements KeyPairService.
func (s defaultKeyPairService) GetPublicKeyPairSet() (jwk.JWKSet, error) {
	keys := make([]jwk.JWK, 0, len(s.Jwks.Keys))
	for _, v := range s.Jwks.Keys {
		key, err := makePublicKey(v)
		if err != nil {
			return jwk.JWKSet{}, err
		}
		keys = append(keys, key.(jwk.JWK))
	}
	return jwk.JWKSet{Keys: keys}, nil
}

func makePublicKey(Jwk jwk.JWK) (interface{}, error) {
	switch Jwk.KTY {
	case jwk.KtyRSA:
		return jwk.JWK{
			KTY: Jwk.KTY,
			E:   Jwk.E,
			USE: Jwk.USE,
			KID: Jwk.KID,
			ALG: Jwk.ALG,
			N:   Jwk.N,
		}, nil
	case jwk.KtyEC:
		return jwk.JWK{
			KTY: Jwk.KTY,
			USE: Jwk.USE,
			CRV: Jwk.CRV,
			KID: Jwk.KID,
			X:   Jwk.X,
			Y:   Jwk.Y,
			ALG: Jwk.ALG,
		}, nil
	case jwk.KtyOct:
		return Jwk, nil
	case jwk.KtyOKP:
		return jwk.JWK{
			KTY: Jwk.KTY,
			USE: Jwk.USE,
			CRV: Jwk.CRV,
			KID: Jwk.KID,
			X:   Jwk.X,
			ALG: Jwk.ALG,
		}, nil
	default:
		return jwk.JWK{}, jwk.ErrUnsupportedKey
	}
}
