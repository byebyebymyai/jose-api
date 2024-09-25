# JOSE API

This is a simple API for working with JWTs. It is built using the [go-kit](https://github.com/go-kit/kit) framework.

## Endpoints

### GET /jwks

This endpoint returns a JSON Web Key Set (JWKS).

#### POST /jwt

This endpoint generates a signed JWT.

## Deployment

### Podman

using makefile to build and run the service

```bash
make build
make run
```

### Kubernetes

1. using cert-manager to generate the certificate
2. using istio to manage the traffic
