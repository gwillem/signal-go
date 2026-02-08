LIBSIGNAL_SRC     := build/libsignal
LIBSIGNAL_VERSION := v0.87.0
LIBSIGNAL_BIN_URL := https://github.com/gwillem/libsignal-bin/releases/download/$(LIBSIGNAL_VERSION)
LIB_DIR           := internal/libsignal/lib
HEADER        := $(LIB_DIR)/libsignal-ffi.h
NIGHTLY_BIN   := $(dir $(shell rustup which --toolchain nightly cargo 2>/dev/null))
CBINDGEN      := $(shell PATH="$(HOME)/.cargo/bin:$$PATH" which cbindgen 2>/dev/null)
NIGHTLY_PATH  := PATH="$(NIGHTLY_BIN):$(HOME)/.cargo/bin:$$PATH"

# Detect current platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    NATIVE_PLATFORM := darwin-arm64
    NATIVE_TARGET   := aarch64-apple-darwin
  endif
endif
ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    NATIVE_PLATFORM := linux-amd64
    NATIVE_TARGET   := x86_64-unknown-linux-musl
  endif
endif

.PHONY: deps deps-all deps-download deps-darwin-arm64 deps-linux-amd64 test clean proto

deps: $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	$(MAKE) deps-$(NATIVE_PLATFORM)

deps-download:
	mkdir -p $(LIB_DIR)/darwin-arm64 $(LIB_DIR)/linux-amd64
	curl -fSL $(LIBSIGNAL_BIN_URL)/libsignal_ffi-darwin-arm64.a -o $(LIB_DIR)/darwin-arm64/libsignal_ffi.a
	curl -fSL $(LIBSIGNAL_BIN_URL)/libsignal_ffi-linux-amd64.a -o $(LIB_DIR)/linux-amd64/libsignal_ffi.a
	curl -fSL $(LIBSIGNAL_BIN_URL)/libsignal-ffi.h -o $(LIB_DIR)/libsignal-ffi.h

deps-all: deps-darwin-arm64 deps-linux-amd64

deps-darwin-arm64: $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	MACOSX_DEPLOYMENT_TARGET=14.0 $(NIGHTLY_PATH) cargo build --release \
		--target aarch64-apple-darwin \
		--manifest-path $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	mkdir -p $(LIB_DIR)/darwin-arm64
	cp $(LIBSIGNAL_SRC)/target/aarch64-apple-darwin/release/libsignal_ffi.a \
		$(LIB_DIR)/darwin-arm64/libsignal_ffi.a
	$(MAKE) header

deps-linux-amd64: $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	$(NIGHTLY_PATH) \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc \
	CMAKE_TOOLCHAIN_FILE=$(CURDIR)/build/x86_64-linux-musl.cmake \
	BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$$(brew --prefix musl-cross)/libexec/x86_64-linux-musl" \
	cargo build --release \
		--target x86_64-unknown-linux-musl \
		--manifest-path $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	mkdir -p $(LIB_DIR)/linux-amd64
	cp $(LIBSIGNAL_SRC)/target/x86_64-unknown-linux-musl/release/libsignal_ffi.a \
		$(LIB_DIR)/linux-amd64/libsignal_ffi.a
	$(MAKE) header

header: $(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml
	cd $(LIBSIGNAL_SRC) && $(NIGHTLY_PATH) "$(CBINDGEN)" --profile release rust/bridge/ffi -o $(CURDIR)/$(HEADER)

$(LIBSIGNAL_SRC)/rust/bridge/ffi/Cargo.toml:
	git submodule update --init $(LIBSIGNAL_SRC)

proto:
	protoc --go_out=. --go_opt=paths=source_relative internal/proto/Provisioning.proto internal/proto/WebSocketResources.proto internal/proto/DeviceName.proto internal/proto/SignalService.proto

test:
	CGO_LDFLAGS_ALLOW='-Wl,-w' CGO_LDFLAGS='-Wl,-w' go test ./... -timeout 10s

clean:
	rm -rf $(LIB_DIR)/darwin-arm64 $(LIB_DIR)/linux-amd64 $(HEADER)
