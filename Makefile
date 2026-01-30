.PHONY: build deploy run clean

BINARY = pxemanager
PXE_SERVER = root@pxe.g10.lo

build:
	go build -o $(BINARY) .

build-linux:
	podman build -f Dockerfile.build -t pxemanager-build .
	podman create --name pxemanager-extract pxemanager-build
	podman cp pxemanager-extract:/build/pxemanager-linux .
	podman rm pxemanager-extract

run: build
	./$(BINARY)

deploy: build-linux
	@echo "Deploying to PXE server..."
	scp $(BINARY)-linux $(PXE_SERVER):/usr/local/bin/pxemanager
	scp pxemanager.service $(PXE_SERVER):/etc/init.d/pxemanager
	ssh $(PXE_SERVER) "chmod +x /etc/init.d/pxemanager && rc-update add pxemanager default && rc-service pxemanager restart"
	@echo "PXE Manager deployed and running on http://pxe.g10.lo:8080"

clean:
	rm -f $(BINARY) $(BINARY)-linux
