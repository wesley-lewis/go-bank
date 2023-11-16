run: build
	@./bin/go-bank

build: 
	@go build -o bin/go-bank

test:
	@go test -v ./...
