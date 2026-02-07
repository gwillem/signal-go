# Updating libsignal

## 1. Build new binaries

Trigger the build in [gwillem/libsignal-bin](https://github.com/gwillem/libsignal-bin):

```bash
gh workflow run build.yml --repo gwillem/libsignal-bin -f libsignal_version=v0.88.0
```

Monitor the build:

```bash
gh run watch --repo gwillem/libsignal-bin
```

This creates a GitHub Release with `libsignal_ffi-darwin-arm64.a`, `libsignal_ffi-linux-amd64.a`, and `libsignal-ffi.h`.

## 2. Update signal-go

1. Update `LIBSIGNAL_VERSION` in `Makefile`
2. Update the git submodule pin: `cd build/libsignal && git checkout v0.88.0`
3. Download the new binaries: `make clean && make deps-download`
4. Run tests: `make test`
5. Fix any breaking API changes (see `docs/todo/done/task11-libsignal-v087-upgrade.md` for past example)
