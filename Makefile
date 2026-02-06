.PHONY: all clean build-rust build-go test run install deploy release

VERSION := 0.1.0
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
	ARCH := arm64
endif

all: build-rust build-go

# Build Rust crypto library
build-rust:
	@echo "Building Rust crypto library..."
	cd crypto-rs && cargo build --release

# Build Go binary
build-go: build-rust
	@echo "Building Go binary..."
	CGO_ENABLED=1 go build -o blocknet .

# Install shared library to system (run 'make all' first, then 'sudo make install')
install:
	@echo "Installing shared library..."
ifeq ($(OS),darwin)
	cp crypto-rs/target/release/libblocknet_crypto.dylib /usr/local/lib/
else
	cp crypto-rs/target/release/libblocknet_crypto.so /usr/local/lib/
	ldconfig
endif

# Build release package for current platform
release: build-rust
	@echo "Building release for $(OS)-$(ARCH)..."
	@mkdir -p releases
	@CGO_ENABLED=1 go build -ldflags="-s -w" -o releases/blocknet .
ifeq ($(OS),darwin)
	@cp crypto-rs/target/release/libblocknet_crypto.dylib releases/
	@cd releases && zip -q blocknet-$(VERSION)-darwin-$(ARCH).zip blocknet libblocknet_crypto.dylib
	@cd releases && shasum -a 256 blocknet-$(VERSION)-darwin-$(ARCH).zip >> SHA256SUMS.txt
	@rm -f releases/blocknet releases/libblocknet_crypto.dylib
	@echo "Built: releases/blocknet-$(VERSION)-darwin-$(ARCH).zip"
else
	@cp crypto-rs/target/release/libblocknet_crypto.so releases/
	@cd releases && zip -q blocknet-$(VERSION)-linux-$(ARCH).zip blocknet libblocknet_crypto.so
	@cd releases && sha256sum blocknet-$(VERSION)-linux-$(ARCH).zip >> SHA256SUMS.txt
	@rm -f releases/blocknet releases/libblocknet_crypto.so
	@echo "Built: releases/blocknet-$(VERSION)-linux-$(ARCH).zip"
endif
	@echo "Checksum added to releases/SHA256SUMS.txt"

# Run tests
test:
	@echo "Testing Rust library..."
	cd crypto-rs && cargo test
	@echo "Testing Go code..."
	./blocknet --test

# Run the project
run: build-go
	./blocknet

# Run as daemon (headless)
daemon: build-go
	./blocknet --daemon

# Run as seed node
seed: build-go
	./blocknet --seed --daemon

# Clean build artifacts
clean:
	@echo "Cleaning..."
	cd crypto-rs && cargo clean
	rm -f blocknet
	rm -rf data/
	rm -rf releases/
	go clean

# Clean everything including wallet
clean-all: clean
	rm -f wallet.dat

# Install dependencies
deps:
	@echo "Installing Rust dependencies..."
	cd crypto-rs && cargo fetch
	@echo "Installing Go dependencies..."
	go mod download

# Deploy to seed node
deploy:
	@echo "Deploying to seed node..."
	rsync -avz --exclude 'target/' --exclude '.git/' --exclude '*.dat' --exclude 'data/' --exclude 'releases/' . blocknet:~/blocknet/
	ssh blocknet "cd ~/blocknet && make build-rust && make install && make build-go"

# Deploy release to website
deploy-release: release
	@echo "Deploying release to website..."
	scp releases/blocknet-$(VERSION)-$(OS)-$(ARCH).zip blocknet:/var/www/blocknet/releases/
	ssh blocknet "cd /var/www/blocknet/releases && cat >> SHA256SUMS.txt" < releases/SHA256SUMS.txt
	@echo "Release deployed to https://blocknetcrypto.com/releases/"
