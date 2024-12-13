
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY main.go .

# Build the binary
RUN go build -o auth-service .

FROM scratch

WORKDIR /app

COPY --from=builder /app/auth-service .

EXPOSE 9191

ENTRYPOINT ["./auth-service"]
