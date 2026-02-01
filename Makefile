LIBSIGNAL_DIR := ../libsignal
LIBSIGNAL_FFI := $(LIBSIGNAL_DIR)/target/release/libsignal_ffi.a
HEADER         := internal/libsignal/libsignal-ffi.h
NIGHTLY_BIN   := $(HOME)/.rustup/toolchains/nightly-aarch64-apple-darwin/bin

.PHONY: build test clean proto

build: $(LIBSIGNAL_FFI) $(HEADER)

$(LIBSIGNAL_FFI): $(LIBSIGNAL_DIR)/rust/bridge/ffi/Cargo.toml
	"$(NIGHTLY_BIN)/cargo" build --release --manifest-path $(LIBSIGNAL_DIR)/rust/bridge/ffi/Cargo.toml

$(HEADER): $(LIBSIGNAL_FFI)
	PATH="$(NIGHTLY_BIN):$(HOME)/.cargo/bin:$$PATH" cbindgen --profile release $(LIBSIGNAL_DIR)/rust/bridge/ffi -o $(HEADER)

proto:
	protoc --go_out=. --go_opt=paths=source_relative internal/proto/Provisioning.proto internal/proto/WebSocketResources.proto

test: build
	CGO_LDFLAGS_ALLOW='-Wl,-w' CGO_LDFLAGS='-Wl,-w' go test ./...

clean:
	rm -f $(HEADER)
	cd $(LIBSIGNAL_DIR) && cargo clean
