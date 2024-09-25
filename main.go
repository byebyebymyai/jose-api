package main

import (
	"crypto/tls"
	"encoding/base64"
	"log/slog"
	"net/http"
	"os"

	"github.com/byebyebymyai/jose-api/entity/jwk"
	"github.com/byebyebymyai/jose-api/middleware"
	httpTransport "github.com/byebyebymyai/jose-api/transport/http"
)

var jwks jwk.JWKSet

func main() {
	logHandler := slog.NewJSONHandler(os.Stdout, nil)
	logger := slog.New(logHandler)

	tokenSvc := defaultTokenService{
		Jwks: jwks,
	}

	keyPairSvc := defaultKeyPairService{
		Jwks: jwks,
	}

	loggingMiddleware := middleware.GeneralLoggingMiddleware(logger)

	signedClaimsHandler := httpTransport.NewServer(
		loggingMiddleware(makeTokenStringsEndpoint(tokenSvc)),
		decodeJwtClaimsRequest,
		encodeTokenStringsResponse,
		httpTransport.ServerBefore(httpTransport.PopulateRequestContext),
	)

	publicKeyPairSetHandler := httpTransport.NewServer(
		loggingMiddleware(makePublicKeyPairSetEndpoint(keyPairSvc)),
		decodePublicKeyPairSetRequest,
		encodePublicKeyPairSetResponse,
		httpTransport.ServerBefore(httpTransport.PopulateRequestContext),
	)

	mux := http.NewServeMux()

	mux.Handle("POST /jwt", signedClaimsHandler)
	mux.Handle("GET /jwks", publicKeyPairSetHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger.Info("[main]", "message", "starting server", "port", 8080)
	http.ListenAndServe(":8080", mux)
}

func init() {
	key := os.Getenv("KEY")
	crt := os.Getenv("CRT")
	alg := os.Getenv("ALG")
	if key == "" {
		panic("KEY is not set")
	}
	if crt == "" {
		panic("CRT is not set")
	}
	if alg == "" {
		panic("ALG is not set")
	}
	isProd := os.Getenv("PROD")

	if isProd == "true" {
		cert, e := tls.X509KeyPair([]byte(crt), []byte(key))
		if e != nil {
			panic(e)
		}
		jwks = jwk.NewJWKSet(jwk.NewJWK(cert, jwk.ALG(alg)))
	} else {
		decodeKey, e := base64.RawURLEncoding.DecodeString(key)
		if e != nil {
			panic(e)
		}
		decodeCrt, e := base64.RawURLEncoding.DecodeString(crt)
		if e != nil {
			panic(e)
		}
		cert, e := tls.X509KeyPair(decodeCrt, decodeKey)
		if e != nil {
			panic(e)
		}
		jwks = jwk.NewJWKSet(jwk.NewJWK(cert, jwk.ALG(alg)))
	}
}
