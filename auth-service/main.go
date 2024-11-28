package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "crypto/sha256"
    "encoding/hex"
    
    envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
    "github.com/go-redis/redis/v8"
    "google.golang.org/grpc"
    "google.golang.org/genproto/googleapis/rpc/status"
)

type AuthServer struct {
    redis *redis.Client
}

func NewAuthServer(redisAddr string) *AuthServer {
    return &AuthServer{
        redis: redis.NewClient(&redis.Options{
            Addr: redisAddr,
        }),
    }
}

func denied(message string) *auth.CheckResponse {
    return &auth.CheckResponse{
        Status: &status.Status{Code: 16},
        HttpResponse: &auth.CheckResponse_DeniedResponse{
            DeniedResponse: &auth.DeniedHttpResponse{
                Status: &envoy_type.HttpStatus{
                    Code: envoy_type.StatusCode_Unauthorized,
                },
                Body: message,
            },
        },
    }
}

func (s *AuthServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
    headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
    
    authHeader := headers["authorization"]
    if !strings.HasPrefix(authHeader, "Basic ") {
        return denied("basic auth required"), nil
    }
    
    credentials := strings.TrimPrefix(authHeader, "Basic ")
    decoded, err := base64.StdEncoding.DecodeString(credentials)
    if err != nil {
        return denied("invalid auth format"), nil
    }
    
    parts := strings.SplitN(string(decoded), ":", 2)
    if len(parts) != 2 {
        return denied("invalid auth format"), nil
    }
    
    username, password := parts[0], parts[1]
    credHash := hashCredentials(username, password)
    
    tenantID, err := s.redis.Get(ctx, credHash).Result()
    if err == redis.Nil {
        return denied("invalid credentials"), nil
    } else if err != nil {
        return denied("internal error"), nil
    }
    
    return &auth.CheckResponse{
        Status: &status.Status{Code: 0},
        HttpResponse: &auth.CheckResponse_OkResponse{
            OkResponse: &auth.OkHttpResponse{
                Headers: []*envoy_config_core.HeaderValueOption{
                    {
                        Header: &envoy_config_core.HeaderValue{
                            Key: "X-Tenant-ID",
                            Value: tenantID,
                        },
                    },
                    {
                        Header: &envoy_config_core.HeaderValue{
                            Key: "X-Scope-OrgID",
                            Value: tenantID,
                        },
                    },
                },
            },
        },
    }, nil
}

func hashCredentials(username, password string) string {
    h := sha256.New()
    h.Write([]byte(fmt.Sprintf("%s:%s", username, password)))
    return hex.EncodeToString(h.Sum(nil))
}

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func main() {
    redisAddr := fmt.Sprintf("%s:%s",
        getEnv("REDIS_HOST", "redis"),
        getEnv("REDIS_PORT", "6379"),
    )
    
    server := NewAuthServer(redisAddr)
    
    grpcServer := grpc.NewServer()
    auth.RegisterAuthorizationServer(grpcServer, server)
    
    lis, err := net.Listen("tcp", ":9191")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    
    log.Printf("auth server listening on :9191")
    if err := grpcServer.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
