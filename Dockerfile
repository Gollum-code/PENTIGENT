# syntax=docker/dockerfile:1

# ---- 前端静态导出 ----
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- Go 单二进制（内嵌前端）----
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/out ./webui/dist
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X pentigent/server.Version=docker" \
    -o /out/pentigent ./cmd/pentigent

# ---- 运行时 ----
FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/pentigent /app/pentigent
COPY config.json /app/config.json
EXPOSE 8080
ENTRYPOINT ["/app/pentigent", "/app/config.json"]
