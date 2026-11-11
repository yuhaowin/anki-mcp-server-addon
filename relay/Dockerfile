FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /anki-mcp-relay .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /anki-mcp-relay /anki-mcp-relay
ENV RELAY_LISTEN=:8080 RELAY_DATA=/data/relay-data.json
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/anki-mcp-relay"]
