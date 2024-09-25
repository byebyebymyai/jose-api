// https://github.com/MicahParks/jwkset/blob/master/marshal.go

package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"time"
)

var (
	// ErrGetX5U indicates there was an error getting the X5U remote resource.
	ErrGetX5U = errors.New("failed to get X5U via given URI")
	// ErrJWKValidation indicates that a JWK failed to validate.
	ErrJWKValidation = errors.New("failed to validate JWK")
	// ErrKeyUnmarshalParameter indicates that a JWK's attributes are invalid and cannot be unmarshaled.
	ErrKeyUnmarshalParameter = errors.New("unable to unmarshal JWK due to invalid attributes")
	// ErrOptions indicates that the given options caused an error.
	ErrOptions = errors.New("the given options caused an error")
	// ErrUnsupportedKey indicates a key is not supported.
	ErrUnsupportedKey = errors.New("unsupported key")
	// ErrX509Mismatch indicates that the X.509 certificate does not match the key.
	ErrX509Mismatch = errors.New("the X.509 certificate does not match Golang key type")
)

type Base64 []byte

// OtherPrimes is for RSA private keys that have more than 2 primes.
// https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
type OtherPrimes struct {
	R string `json:"r,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
	D string `json:"d,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	T string `json:"t,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
}

// JWK is used to marshal or unmarshal a JSON Web Key.
// https://www.rfc-editor.org/rfc/rfc7517
// https://www.rfc-editor.org/rfc/rfc7518
// https://www.rfc-editor.org/rfc/rfc8037
//
// You can find the full list at https://www.iana.org/assignments/jose/jose.xhtml under "JSON Web Key Parameters".
type JWK struct {
	KTY     KTY           `json:"kty,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	USE     USE           `json:"use,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	KEYOPS  []KEYOPS      `json:"key_ops,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	ALG     ALG           `json:"alg,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.4 and https://www.rfc-editor.org/rfc/rfc7518#section-4.1
	KID     string        `json:"kid,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	X5U     string        `json:"x5u,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	X5C     []string      `json:"x5c,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.7
	X5T     string        `json:"x5t,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.8
	X5TS256 string        `json:"x5t#S256,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.9
	CRV     CRV           `json:"crv,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	X       Base64        `json:"x,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	Y       Base64        `json:"y,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
	D       Base64        `json:"d,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	N       Base64        `json:"n,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	E       Base64        `json:"e,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	P       Base64        `json:"p,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q       Base64        `json:"q,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	DP      Base64        `json:"dp,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ      Base64        `json:"dq,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	QI      Base64        `json:"qi,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	OTH     []OtherPrimes `json:"oth,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	K       Base64        `json:"k,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func (b64 *Base64) UnmarshalJSON(data []byte) error {
	var any interface{}
	err := json.Unmarshal(data, &any)
	if err != nil {
		return err
	}
	switch v := any.(type) {
	case string:
		decode, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return err
		}
		*b64 = decode
		return nil
	default:
		return ErrKeyUnmarshalParameter
	}
}

func (b64 *Base64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(*b64))
}

func (jwk *JWK) PublicKey() interface{} {
	switch jwk.KTY {
	case KtyEC:
		return ecdsa.PublicKey{
			X: new(big.Int).SetBytes(jwk.X),
			Y: new(big.Int).SetBytes(jwk.Y),
		}
	case KtyOKP:
		return ed25519.PublicKey(jwk.X)
	case KtyRSA:
		return rsa.PublicKey{
			N: new(big.Int).SetBytes(jwk.N),
			E: int(new(big.Int).SetBytes(jwk.E).Uint64()),
		}
	case KtyOct:
		return jwk.K
	default:
		return nil
	}
}

func (jwk *JWK) PrivateKey() interface{} {
	switch jwk.KTY {
	case KtyEC:
		return ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				X: new(big.Int).SetBytes(jwk.X),
				Y: new(big.Int).SetBytes(jwk.Y),
			},
			D: new(big.Int).SetBytes(jwk.D),
		}
	case KtyOKP:
		return ed25519.PrivateKey(jwk.D)
	case KtyRSA:
		return &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: new(big.Int).SetBytes(jwk.N),
				E: int(new(big.Int).SetBytes(jwk.E).Uint64()),
			},
			D: new(big.Int).SetBytes(jwk.D),
			Primes: []*big.Int{
				new(big.Int).SetBytes(jwk.P),
				new(big.Int).SetBytes(jwk.Q),
			},
			Precomputed: rsa.PrecomputedValues{
				Dp:   new(big.Int).SetBytes(jwk.DP),
				Dq:   new(big.Int).SetBytes(jwk.DQ),
				Qinv: new(big.Int).SetBytes(jwk.QI),
			},
		}
	case KtyOct:
		return jwk.K
	default:
		return nil
	}
}

func (jwk *JWK) X509() []*x509.Certificate {
	x5c := make([]*x509.Certificate, len(jwk.X5C))
	for i, cert := range jwk.X5C {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil
		}
		x5c[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil
		}
	}
	return x5c
}

func ValidateJWK(Jwk JWK) error {
	switch Jwk.KTY {
	case KtyRSA:
		if Jwk.ALG == "" || Jwk.KID == "" {
			return ErrJWKValidation
		}
		if Jwk.ALG != AlgRS256 && Jwk.ALG != AlgRS384 && Jwk.ALG != AlgRS512 {
			return ErrJWKValidation
		}
		if len(Jwk.N) == 0 || len(Jwk.E) == 0 || len(Jwk.D) == 0 {
			return ErrJWKValidation
		}
		if len(Jwk.P) == 0 || len(Jwk.Q) == 0 || len(Jwk.DP) == 0 || len(Jwk.DQ) == 0 || len(Jwk.QI) == 0 {
			return ErrJWKValidation
		}
		if len(Jwk.OTH) > 0 {
			for _, other := range Jwk.OTH {
				if other.R == "" || other.D == "" || other.T == "" {
					return ErrJWKValidation
				}
			}
		}
	case KtyEC:
		if Jwk.CRV == "" || Jwk.ALG == "" || Jwk.KID == "" {
			return ErrJWKValidation
		}
		if Jwk.ALG != AlgES256 && Jwk.ALG != AlgES384 && Jwk.ALG != AlgES512 {
			return ErrJWKValidation
		}
		if Jwk.CRV == "" || len(Jwk.X) == 0 || len(Jwk.Y) == 0 {
			return ErrJWKValidation
		}
		if len(Jwk.D) > 0 {
			return ErrJWKValidation
		}
	case KtyOKP:
		if Jwk.CRV == "" || Jwk.ALG == "" || Jwk.KID == "" {
			return ErrJWKValidation
		}
		if Jwk.ALG != AlgEdDSA {
			return ErrJWKValidation
		}
		if Jwk.CRV == "" || len(Jwk.X) == 0 {
			return ErrJWKValidation
		}
	default:
		return ErrUnsupportedKey
	}
	return nil
}

func NewJWK(cert tls.Certificate, alg ALG) JWK {
	switch privKey := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return JWK{
			KTY: KtyRSA,
			ALG: alg,
			USE: UseSig,
			KID: strconv.FormatInt(time.Now().Unix(), 10),
			D:   Base64(privKey.D.Bytes()),
			N:   Base64(privKey.N.Bytes()),
			E:   Base64(big.NewInt(int64(privKey.E)).Bytes()),
			P:   Base64(privKey.Primes[0].Bytes()),
			Q:   Base64(privKey.Primes[1].Bytes()),
			DP:  Base64(privKey.Precomputed.Dp.Bytes()),
			DQ:  Base64(privKey.Precomputed.Dq.Bytes()),
			QI:  Base64(privKey.Precomputed.Qinv.Bytes()),
		}
	case *ecdsa.PrivateKey:
		return JWK{
			KTY: KtyEC,
			ALG: alg,
			USE: UseSig,
			KID: strconv.FormatInt(time.Now().Unix(), 10),
			CRV: CrvP256,
			X:   Base64(privKey.X.Bytes()),
			Y:   Base64(privKey.Y.Bytes()),
			D:   Base64(privKey.D.Bytes()),
		}
	case ed25519.PrivateKey:
		return JWK{
			KTY: KtyOKP,
			ALG: alg,
			USE: UseSig,
			KID: strconv.FormatInt(time.Now().Unix(), 10),
			CRV: CrvEd25519,
			X:   Base64(privKey.Public().(ed25519.PublicKey)),
			D:   Base64(privKey),
		}
	default:
		return JWK{}
	}
}

func NewJWKSet(jwks ...JWK) JWKSet {
	for _, jwk := range jwks {
		if err := ValidateJWK(jwk); err != nil {
			panic(err)
		}
	}
	return JWKSet{Keys: jwks}
}
