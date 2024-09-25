package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/byebyebymyai/jose-api/endpoint"
)

// JwtGeneratorEndpoint is a single request endpoint that generates a JWT token.
// With adding the "iat" (issued at) and "jti" (JWT ID) claims to the request, the endpoint generates a JWT token.
// https://www.iana.org/assignments/jwt/jwt.xhtml
func makeTokenStringsEndpoint(s TokenService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if tokenStrings, err := s.MakeTokenStrings(request.(jwt.MapClaims)); err != nil {
			return nil, err
		} else {
			return tokenStrings, nil
		}
	}
}

func decodeJwtClaimsRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if r.Body == http.NoBody {
		return nil, errors.New("request body is empty")
	}
	var request jwt.MapClaims
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func encodeTokenStringsResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	for _, value := range response.([]string) {
		w.Header().Set("Authorization", "Bearer "+value)
	}
	return nil
}

func makePublicKeyPairSetEndpoint(s KeyPairService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		return s.GetPublicKeyPairSet()
	}
}

func decodePublicKeyPairSetRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return struct{}{}, nil
}

func encodePublicKeyPairSetResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}
