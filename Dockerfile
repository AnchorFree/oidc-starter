FROM golang:1.11.4-alpine3.8 as builder

ENV GO111MODULE on
ENV PROJECT_NAME oidc-starter

RUN apk --no-cache add git

WORKDIR /go/src/${PROJECT_NAME}
COPY go.mod go.sum /go/src/${PROJECT_NAME}/
RUN go mod download
COPY . /go/src/${PROJECT_NAME}
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /build/${PROJECT_NAME}

FROM alpine:3.8
ENV BINARY oidc-starter
EXPOSE 5555
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/${BINARY} /bin/${BINARY}

ENTRYPOINT ["/bin/oidc-starter"]
