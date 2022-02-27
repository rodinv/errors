FROM golang:1.17 AS builder

RUN mkdir /src /app

WORKDIR /src
COPY . /src

RUN go mod download
RUN go get golang.org/x/tools/cmd/goimports
COPY --from=golangci/golangci-lint:latest /usr/bin/golangci-lint /usr/bin/golangci-lint

RUN go fmt $(go list ./...)
RUN go vet $(go list ./...)
RUN code=1; out=$(goimports -d -local github.com/pkg/errors ./); \
    if [ -z "$out" ]; then code=0; fi; echo "$out"; exit $code;
RUN golangci-lint run

RUN go test -race ./... -cover -coverprofile=cov.out
RUN go tool cover -func cov.out | grep total | awk '{print $3}' | awk -F '%' \
    'BEGIN { code = 1 } \
    { if ($1 < 100) print "Write tests for your code!"; else code = 0 } \
    END { exit code }'
