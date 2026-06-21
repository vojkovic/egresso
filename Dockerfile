FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /egresso ./cmd/egresso

FROM gcr.io/distroless/static-debian12
COPY --from=build /egresso /egresso
ENTRYPOINT ["/egresso"]
