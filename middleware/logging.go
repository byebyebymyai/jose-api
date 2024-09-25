package middleware

import (
	"context"
	"log/slog"
	"time"

	"github.com/byebyebymyai/jose-api/endpoint"
	httpTransport "github.com/byebyebymyai/jose-api/transport/http"
)

func GeneralLoggingMiddleware(logger *slog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			response, err := next(ctx, request)
			defer func(begin time.Time) {
				logger.Info("[GeneralLoggingMiddleware]",
					"method", ctx.Value(httpTransport.ContextKeyRequestMethod),
					"uri", ctx.Value(httpTransport.ContextKeyRequestURI),
					"path", ctx.Value(httpTransport.ContextKeyRequestPath),
					"proto", ctx.Value(httpTransport.ContextKeyRequestProto),
					"host", ctx.Value(httpTransport.ContextKeyRequestHost),
					"remote_addr", ctx.Value(httpTransport.ContextKeyRequestRemoteAddr),
					"authorization", ctx.Value(httpTransport.ContextKeyRequestAuthorization),
					"referer", ctx.Value(httpTransport.ContextKeyRequestReferer),
					"user_agent", ctx.Value(httpTransport.ContextKeyRequestUserAgent),
					"accept", ctx.Value(httpTransport.ContextKeyRequestAccept),
					"request", request,
					"response", response,
					"error", err,
					"took", time.Since(begin))
			}(time.Now())
			return response, err
		}
	}
}
