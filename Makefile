.PHONY: build deploy run clean

BINARY = pxemanager

build:
	go build -o $(BINARY) .

run: build
	./$(BINARY)

deploy:
	./deploy.sh

clean:
	rm -f $(BINARY)
