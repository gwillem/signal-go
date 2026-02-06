#ifndef BRIDGE_H
#define BRIDGE_H

// Cast helpers for SignalServiceIdFixedWidthBinaryBytes.
// CGO maps this typedef (uint8_t[17]) differently across platforms,
// so we cast through void* in C where the types always match.
static inline const SignalServiceIdFixedWidthBinaryBytes* as_service_id(const void *p) {
    return (const SignalServiceIdFixedWidthBinaryBytes*)p;
}

static inline SignalServiceIdFixedWidthBinaryBytes* as_mut_service_id(void *p) {
    return (SignalServiceIdFixedWidthBinaryBytes*)p;
}

#endif
