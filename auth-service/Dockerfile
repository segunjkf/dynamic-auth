# auth-service/Dockerfile
FROM golang:1.21-alpine

WORKDIR /app

# Copy go mod files first to leverage caching
COPY go.mod .
COPY main.go .

# Initialize and build
RUN go mod tidy && \
    go build -o auth-service

EXPOSE 9191

CMD ["./auth-service"]