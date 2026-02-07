# Building from source

## Prerequisites

- Go 1.25+
- Rust nightly (`rustup install nightly-2025-09-24`)
- cbindgen (`cargo install cbindgen`)
- Native target: `rustup target add aarch64-apple-darwin --toolchain nightly-2025-09-24`

## Build & test

```bash
git submodule update --init   # fetch libsignal source (first time only)
make deps                     # builds libsignal_ffi.a + generates headers (native platform)
make test                     # runs tests with correct CGO flags
```

## Cross-compile for Linux (static)

Requires [musl-cross](https://github.com/FiloSottile/homebrew-musl-cross) on macOS:

```bash
brew install FiloSottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl --toolchain nightly-2025-09-24
make deps-linux-amd64
CGO_ENABLED=1 CC=x86_64-linux-musl-gcc GOOS=linux GOARCH=amd64 \
  go build -ldflags '-extldflags "-static"' -o sgnl-linux ./cmd/sgnl
```
