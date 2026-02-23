.PHONY: build deploy run clean

BINARY = pxemanager

build:
	./build.sh

run:
	go build -o $(BINARY) .
	./$(BINARY)

deploy:
	./deploy.sh

clean:
	rm -f $(BINARY)
