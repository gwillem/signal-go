#include "libsignal-ffi.h"
#include "_cgo_export.h"

// bridge_cdsi_lookup_new_complete is called by Rust when signal_cdsi_lookup_new completes.
// It extracts the raw pointer from the wrapper struct and forwards to Go.
void bridge_cdsi_lookup_new_complete(SignalFfiError *err, const SignalMutPointerCdsiLookup *result, const void *ctx) {
    SignalCdsiLookup *raw = NULL;
    if (result != NULL) {
        raw = result->raw;
    }
    goCdsiLookupNewComplete(err, raw, (void *)ctx);
}

// bridge_cdsi_response_complete is called by Rust when signal_cdsi_lookup_complete completes.
// It forwards the response pointer to Go. Go must copy data before returning since
// Rust may free the response after callback returns.
void bridge_cdsi_response_complete(SignalFfiError *err, const SignalFfiCdsiLookupResponse *result, const void *ctx) {
    goCdsiResponseComplete(err, (SignalFfiCdsiLookupResponse *)result, (void *)ctx);
}
