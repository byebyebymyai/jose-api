# syntax=docker/dockerfile:1

FROM golang:1.23.1 as builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /app


FROM gcr.io/distroless/base-debian12

WORKDIR /

COPY --from=builder /app /app

EXPOSE 8080

ENTRYPOINT ["/app"]




