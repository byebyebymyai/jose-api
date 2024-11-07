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

1. Using cert-manager to Generate PEM Secret for signing JWT

```bash
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: self-signed-issuer
  namespace: istio-auth
spec:
  selfSigned: {}
EOF

kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: jwk-rsa-cert
  namespace: istio-auth
spec:
  secretName: jwk-rsa
  commonName: jwa-rsa.istio-auth.svc.cluster.local
  isCA: false
  usages:
    - signing
    - client auth
  privateKey:
    algorithm: RSA
    encoding: PKCS8
    size: 2048
  issuerRef:
    name: self-signed-issuer
    kind: Issuer
    group: cert-manager.io
EOF

# Check the secret
kubectl get secret jwk-rsa -n istio-auth -o jsonpath='{.data.tls\.key}' | base64 -d
kubectl get secret jwk-rsa -n istio-auth -o jsonpath='{.data.tls\.crt}' | base64 -d
```

2. Deploy the Service

```bash
# Create ConfigMap
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: jose-api-config
  namespace: istio-auth
data:
  algorithm: RS256
  is_production: "true"
EOF
```

```bash
# Create ServiceAccount
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: jose-api
  namespace: istio-auth
EOF
```

```bash
# Create Service
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: jose-api
  namespace: istio-auth
spec:
  selector:
    app: jose-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
EOF
```

```bash
# Create Deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jose-api
  namespace: istio-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jose-api
  template:
    metadata:
      labels:
        app: jose-api
    spec:
      containers:
      - name: jose-api
        image: ghcr.io/byebyebymyai/jose-api:main
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        env:
        - name: KEY
          valueFrom:
            secretKeyRef:
              name: jwk-rsa
              key: tls.key
        - name: CRT
          valueFrom:
            secretKeyRef:
              name: jwk-rsa
              key: tls.crt
        - name: ALG
          valueFrom:
            configMapKeyRef:
              name: jose-api-config
              key: algorithm
        - name: PROD
          valueFrom:
            configMapKeyRef:
              name: jose-api-config
              key: is_production
EOF
```

3. Test Jose API Service

```bash
# Using kubectl proxy to access the service
kubectl proxy

# Test token generation method
TOKEN=$(curl -is  -X POST http://localhost:8001/api/v1/namespaces/istio-auth/services/jose-api:80/proxy/jwt -H "Content-Type: application/json" -d '{"username": "test"}' | grep Authorization: | awk '{print $3}')

echo "$TOKEN" | cut -d '.' -f2 - | base64 --decode

# Test jwks.json
curl -is  http://localhost:8001/api/v1/namespaces/istio-auth/services/jose-api:80/proxy/jwks.json
```
