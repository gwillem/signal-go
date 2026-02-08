# Task 23: Dead Code Cleanup

## Status: Planned

## Problem

As the codebase has evolved through multiple phases, unused functions, types, and methods may have accumulated. The `deadcode` tool (`golang.org/x/tools/cmd/deadcode`) can identify unreachable code across the module.

## Steps

1. Run `deadcode ./...` and capture output
2. Review each reported symbol — categorize as:
   - **Safe to remove**: truly unused, no future plans
   - **Used by tests only**: may still be needed
   - **Planned for future use**: referenced in task docs, keep for now
3. Remove confirmed dead code
4. Run `make test` to verify nothing breaks

## Notes

- `deadcode` is whole-program analysis — it finds functions that are never called from any `main` package
- Library functions called only from tests may show up; these are not dead
- CGO export functions (`//export`) may be flagged incorrectly — skip those
- Check `cmd/sgnl/` and `cmd/wiwiclaw/` entry points are included in analysis
