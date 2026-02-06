# Task 16: Streamline libsignal build process

## Status: DONE

## Goal

Replace the current ad-hoc build setup (requiring `../libsignal` sibling checkout, hardcoded nightly toolchain path) with a self-contained, multi-architecture build via `make deps` and `make deps-all`.

## Current state

- libsignal source expected at `../libsignal` (sibling directory, manually cloned)
- Makefile hardcodes `NIGHTLY_BIN` to `aarch64-apple-darwin` nightly toolchain path
- CGO directives in `internal/libsignal/libsignal.go` hardcode path to `../../../libsignal/target/release/libsignal_ffi.a`
- Only one architecture supported (whatever the host machine is)
- Header (`libsignal-ffi.h`) lives in `internal/libsignal/`

## Design

### Directory layout

```
signal-go/
  build/libsignal/                         # git submodule (pinned to v0.87.0 = ec3aa082)
  internal/libsignal/
    lib/
      darwin-arm64/libsignal_ffi.a       # built artefacts (gitignored)
      linux-amd64/libsignal_ffi.a
      libsignal-ffi.h                    # generated header (arch-independent)
    libsignal.go                         # CGO preamble (updated)
```

### Git submodule

Add libsignal as a submodule at `./build/libsignal` (keeps build artifacts together), pinned to tag `v0.87.0` (commit `ec3aa082`):

```bash
git submodule add https://github.com/signalapp/libsignal.git build/libsignal
cd build/libsignal && git checkout v0.87.0
```

### Makefile targets

#### `make deps` (current architecture)

1. `git submodule update --init` if `build/libsignal/` is empty
2. Detect current OS/arch: `GOOS`/`GOARCH` or `uname`
3. Map to Rust target triple (e.g., `darwin-arm64` -> `aarch64-apple-darwin`)
4. Run `cargo +nightly build --release --target <triple>` in `build/libsignal/rust/bridge/ffi/`
5. Copy `.a` to `internal/libsignal/lib/<os>-<arch>/libsignal_ffi.a`
6. Run `cbindgen` to generate `internal/libsignal/lib/libsignal-ffi.h`

#### `make deps-all` (both architectures)

Build for both targets:

- `darwin-arm64` -> Rust target `aarch64-apple-darwin`
- `linux-amd64` -> Rust target `x86_64-unknown-linux-musl`

The linux-amd64 cross-build requires:

- `rustup target add x86_64-unknown-linux-musl`
- `brew install FiloSottile/musl-cross/musl-cross` (provides `x86_64-linux-musl-gcc`)
- Set `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc`

### CGO preamble changes

Update `internal/libsignal/libsignal.go` to use platform-specific paths:

```go
// #cgo CFLAGS: -I${SRCDIR}/lib
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/lib/darwin-arm64/libsignal_ffi.a -framework Security -framework Foundation -lm
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/linux-amd64/libsignal_ffi.a -ldl -lm -lpthread
// #include "libsignal-ffi.h"
// #include <stdlib.h>
import "C"
```

Go's `#cgo` directives support build constraint tags (`darwin,arm64` / `linux,amd64`), so the linker automatically picks the right `.a` for the build target. The `-I${SRCDIR}/lib` ensures the header is found in its new location. This also enables `GOOS=linux GOARCH=amd64 go build` cross-compilation from macOS.

## Implementation steps

1. **Add git submodule** — `git submodule add https://github.com/signalapp/libsignal.git build/libsignal`, checkout `v0.87.0`, commit `.gitmodules`
2. **Create artefact directories** — `internal/libsignal/lib/darwin-arm64/`, `internal/libsignal/lib/linux-amd64/`, add to `.gitignore`
3. **Move header** — Move `internal/libsignal/libsignal-ffi.h` to `internal/libsignal/lib/libsignal-ffi.h`
4. **Rewrite Makefile** — Replace current `build` target with `deps` and `deps-all`, remove hardcoded `NIGHTLY_BIN` path, auto-detect architecture
5. **Update CGO preamble** — Change `libsignal.go`: CFLAGS `-I${SRCDIR}/lib`, platform-specific LDFLAGS pointing to `lib/<os>-<arch>/`
6. **Update .gitignore** — Ignore `internal/libsignal/lib/` artefacts, ensure `build/libsignal/` submodule is tracked
7. **Update `make test`** — Should depend on `deps` instead of `build`
8. **Remove old `../libsignal` references** — Clean up any remaining sibling-directory references
9. **Test** — Verify `make deps && make test` works on macOS arm64
10. **Update docs** — Update CLAUDE.md prerequisites and building sections

## Platform mapping

| GOOS/GOARCH  | Rust target               | Linker                | Extra LDFLAGS                                 |
| ------------ | ------------------------- | --------------------- | --------------------------------------------- |
| darwin/arm64 | aarch64-apple-darwin      | (default)             | -framework Security -framework Foundation -lm |
| linux/amd64  | x86_64-unknown-linux-musl | x86_64-linux-musl-gcc | -ldl -lm -lpthread                            |

## Prerequisites (updated)

- Go 1.25+
- Rust nightly toolchain (`rustup install nightly`)
- cbindgen (`cargo install cbindgen`)
- For linux-amd64 cross-build: `brew install FiloSottile/musl-cross/musl-cross`, `rustup target add x86_64-unknown-linux-musl`

# Extra TODO

- [ ] ensure the Makefile works on linux too (eg thins line depends on brew: BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$$(brew --prefix musl-cross)/libexec/x86_64-linux-musl")
