
package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "time"
    "crypto/sha256"
    "encoding/hex"

    core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
    "github.com/redis/go-redis/v9"
    "google.golang.org/grpc"
    "google.golang.org/genproto/googleapis/rpc/status"
    "go.uber.org/zap"
)

// AuthServer implements the Envoy external auth service.
// It validates requests using Redis for credential storage.
type AuthServer struct {
    redis  *redis.Client 
    logger *zap.Logger 
}

// AuthResult represents the outcome of an authentication attempt
type AuthResult struct {
    TenantID string
    Allow    bool 
    Error    error
}

// NewAuthServer creates a new AuthServer instance with Redis connection
func NewAuthServer(redisAddr string, logger *zap.Logger) (*AuthServer, error) {
    // Initialize Redis client with timeouts and connection pooling
    redisClient := redis.NewClient(&redis.Options{
        Addr:         redisAddr,
        Password:     "",
        DB:           0,
        DialTimeout:  5 * time.Second,
        ReadTimeout:  3 * time.Second,
        WriteTimeout: 3 * time.Second,
        PoolSize:     10,
        MinIdleConns: 5, 
    })

    // Test Redis connection on startup
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := redisClient.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis connection failed: %w", err)
    }

    return &AuthServer{
        redis:  redisClient,
        logger: logger,
    }, nil
}

// Close gracefully shuts down the auth server
func (s *AuthServer) Close() {
    if err := s.redis.Close(); err != nil {
        s.logger.Error("error closing redis connection", zap.Error(err))
    }
}

// Check implements the Envoy external auth service Check RPC
// This is called by Envoy for every request that needs authentication
func (s *AuthServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
    start := time.Now()
    defer func() {
        s.logger.Debug("auth check completed",
            zap.Duration("duration", time.Since(start)))
    }()

    result := s.validateRequest(ctx, req)
    if !result.Allow {
        s.logger.Warn("auth denied",
            zap.String("tenant", result.TenantID),
            zap.Error(result.Error))
        return denied(result.Error.Error()), nil
    }

    path := req.GetAttributes().GetRequest().GetHttp().GetPath()
    headers := []*core.HeaderValueOption{}

    // Add appropriate headers based on the path
    if strings.HasPrefix(path, "/loki/api/v1/push") {
        headers = append(headers, &core.HeaderValueOption{
            Header: &core.HeaderValue{
                Key:   "X-Scope-OrgID",
                Value: result.TenantID,
            },
        })
    } else if strings.HasPrefix(path, "/api/v1/receive") {
        headers = append(headers, &core.HeaderValueOption{
            Header: &core.HeaderValue{
                Key:   "X-Scope-OrgID",
                Value: result.TenantID,
            },
        })
    }

    s.logger.Info("auth successful",
        zap.String("tenant", result.TenantID),
        zap.String("path", path))

    return &auth.CheckResponse{
        Status: &status.Status{Code: 0},
        HttpResponse: &auth.CheckResponse_OkResponse{
            OkResponse: &auth.OkHttpResponse{
                Headers: headers,
            },
        },
    }, nil
}

// validateRequest performs the actual authentication logic
func (s *AuthServer) validateRequest(ctx context.Context, req *auth.CheckRequest) AuthResult {
    // Get request headers from the auth request
    headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
    
    // Check for Basic Auth header
    authHeader := headers["authorization"]
    if !strings.HasPrefix(authHeader, "Basic ") {
        return AuthResult{Error: fmt.Errorf("basic auth required")}
    }
    
    // Decode Base64 Basic Auth credentials
    credentials := strings.TrimPrefix(authHeader, "Basic ")
    decoded, err := base64.StdEncoding.DecodeString(credentials)
    if err != nil {
        return AuthResult{Error: fmt.Errorf("invalid auth format")}
    }
    
    // Split into username and password
    parts := strings.SplitN(string(decoded), ":", 2)
    if len(parts) != 2 {
        return AuthResult{Error: fmt.Errorf("invalid auth format")}
    }
    
    username, password := parts[0], parts[1]
    
    // Hash credentials for Redis lookup
    credHash := hashCredentials(username, password)
    
    // Look up tenant ID in Redis with timeout
    redisCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    
    // Try to get tenant ID from Redis
    tenantID, err := s.redis.Get(redisCtx, credHash).Result()
    if err == redis.Nil {
        return AuthResult{Error: fmt.Errorf("invalid credentials")}
    } else if err != nil {
        s.logger.Error("redis error", zap.Error(err))
        return AuthResult{Error: fmt.Errorf("internal error")}
    }
    
    // Return success with tenant ID
    return AuthResult{
        TenantID: tenantID,
        Allow:    true,
    }
}

// denied creates a denied response with given message
func denied(message string) *auth.CheckResponse {
    return &auth.CheckResponse{
        Status: &status.Status{Code: 16},  // 16 is permission denied in gRPC
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

// hashCredentials creates a hash of username and password for Redis lookup
func hashCredentials(username, password string) string {
    h := sha256.New()
    h.Write([]byte(fmt.Sprintf("%s:%s", username, password)))
    return hex.EncodeToString(h.Sum(nil))
}

// setupLogger initializes the zap logger
func setupLogger() (*zap.Logger, error) {
    logConfig := zap.NewProductionConfig()
    logConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
    // Use development logger if specified
    if os.Getenv("LOG_FORMAT") == "dev" {
        logConfig = zap.NewDevelopmentConfig()
    }
    return logConfig.Build()
}

func main() {
    // Initialize logger
    logger, err := setupLogger()
    if err != nil {
        log.Fatalf("failed to init logger: %v", err)
    }
    defer logger.Sync()

    // Get Redis address from environment or use default
    redisAddr := fmt.Sprintf("%s:%s",
        getEnv("REDIS_HOST", "redis"),
        getEnv("REDIS_PORT", "6379"),
    )
    
    // Create and initialize auth server
    server, err := NewAuthServer(redisAddr, logger)
    if err != nil {
        logger.Fatal("failed to create auth server", zap.Error(err))
    }
    defer server.Close()
    
    // Create gRPC server with logging interceptor
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(loggingInterceptor(logger)),
    )
    auth.RegisterAuthorizationServer(grpcServer, server)
    
    lis, err := net.Listen("tcp", ":9191")
    if err != nil {
        logger.Fatal("failed to listen", zap.Error(err))
    }
    
    logger.Info("auth server starting", zap.String("address", ":9191"))
    if err := grpcServer.Serve(lis); err != nil {
        logger.Fatal("failed to serve", zap.Error(err))
    }
}

// loggingInterceptor creates a gRPC interceptor for request logging
func loggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        start := time.Now()
        resp, err := handler(ctx, req)
        duration := time.Since(start)
        
        // Log each gRPC request
        logger.Debug("grpc request",
            zap.String("method", info.FullMethod),
            zap.Duration("duration", duration),
            zap.Error(err))
        
        return resp, err
    }
}

// getEnv gets an environment variable with a fallback value
func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}
