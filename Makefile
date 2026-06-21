.PHONY: build test fmt clean

build:
	go build -o egresso ./cmd/egresso

test:
	go test ./...

fmt:
	gofmt -w .

clean:
	rm -f egresso
