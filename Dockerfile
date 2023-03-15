FROM golang:1.20.2-alpine3.17 as builder

ENV PROJECT_NAME oidc-starter

WORKDIR /go/src/${PROJECT_NAME}
COPY go.mod go.sum /go/src/${PROJECT_NAME}/
RUN go mod download
COPY . /go/src/${PROJECT_NAME}
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /build/${PROJECT_NAME}

FROM alpine:3.17
ENV BINARY oidc-starter
EXPOSE 5555

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /go/src/${BINARY}/web web
COPY --from=builder /build/${BINARY} bin/${BINARY}

ENTRYPOINT ["/app/bin/oidc-starter"]
