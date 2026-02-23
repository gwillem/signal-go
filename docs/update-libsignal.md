# Updating libsignal

## 0. Find the latest version

```bash
git -C build/libsignal fetch --tags
git -C build/libsignal describe --tags --abbrev=0 origin/main
```

## 1. Update signal-go locally

1. Update the git submodule pin (replace `$VERSION` with the tag from step 0):
   ```bash
   git -C build/libsignal checkout $VERSION
   ```
2. Build locally from the submodule: `make clean && make deps`
3. Run tests: `make test`
4. Fix any breaking API changes (see `docs/todo/done/task11-libsignal-v087-upgrade.md` for past example)

## 2. Publish pre-built binaries

Once everything compiles and tests pass, trigger the cross-platform build in [gwillem/libsignal-bin](https://github.com/gwillem/libsignal-bin):

```bash
gh workflow run build.yml --repo gwillem/libsignal-bin -f libsignal_version=$VERSION
```

Monitor the build:

```bash
gh run watch --repo gwillem/libsignal-bin
```

This creates a GitHub Release with `libsignal_ffi-darwin-arm64.a`, `libsignal_ffi-linux-amd64.a`, and `libsignal-ffi.h`.

## 3. Finalize

1. Update `LIBSIGNAL_VERSION` in `Makefile` to match the new release
2. Verify download works: `make clean && make deps-download`
3. Run tests again: `make test`
