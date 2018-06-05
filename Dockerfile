FROM golang:1.10-alpine as builder

ENV PROJECT_NAME oidc-starter

COPY . /go/src/github.com/anchorfree/${PROJECT_NAME}
RUN cd /go/src/github.com/anchorfree/${PROJECT_NAME} \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /build/${PROJECT_NAME}

FROM alpine
ENV BINARY oidc-starter
EXPOSE 5555
RUN apk update && apk add ca-certificates
COPY --from=builder /build/${BINARY} /bin/${BINARY}

ENTRYPOINT ["/bin/oidc-starter"]
