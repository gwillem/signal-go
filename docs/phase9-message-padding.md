# Phase 9: Signal Transport Padding

## Status: Complete

## Problem

Messages were being sent and accepted by the server (200 OK), but recipients could not decrypt them. Recipients sent back retry receipts (DecryptionErrorMessage) in an infinite loop.

## Root Cause

Signal-Android applies transport-level padding to all message content **before** encryption. This padding uses a specific format:

```
[content bytes] [0x80 terminator] [0x00 padding...] → padded to 80-byte blocks
```

The padding size is calculated as:
```java
// From PushTransportDetails.java
int getPaddedMessageLength(int messageLength) {
    int messageLengthWithTerminator = messageLength + 1;
    int messagePartCount = messageLengthWithTerminator / 80;
    if (messageLengthWithTerminator % 80 != 0) {
        messagePartCount++;
    }
    return messagePartCount * 80;
}

byte[] getPaddedMessageBody(byte[] messageBody) {
    // The +1 -1 accounts for the cipher's own padding byte
    byte[] paddedMessage = new byte[getPaddedMessageLength(messageBody.length + 1) - 1];
    System.arraycopy(messageBody, 0, paddedMessage, 0, messageBody.length);
    paddedMessage[messageBody.length] = (byte)0x80;
    return paddedMessage;
}
```

We were encrypting raw protobuf bytes without this padding. The recipient would decrypt successfully (Signal protocol level), but then fail to parse the content because it expected the padding format.

## Solution

Added `padMessage()` function in `sender.go` that matches Signal-Android's `PushTransportDetails.getPaddedMessageBody()`:

```go
const paddingBlockSize = 80

func padMessage(messageBody []byte) []byte {
    paddedLen := getPaddedMessageLength(len(messageBody)+1) - 1
    padded := make([]byte, paddedLen)
    copy(padded, messageBody)
    padded[len(messageBody)] = 0x80
    return padded
}
```

The `encryptAndSend()` function now pads content before encryption:

```go
paddedContent := padMessage(contentBytes)
ciphertext, err := libsignal.Encrypt(paddedContent, addr, st, st, now)
```

## Signal-Android Reference

- **File:** `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/PushTransportDetails.java`
- **Test:** `lib/libsignal-service/src/test/java/org/whispersystems/signalservice/api/push/PushTransportDetailsTest.kt`

## Padding Length Examples

| Content Size | Padded Size |
|-------------|-------------|
| 0-78 bytes  | 79 bytes    |
| 79-158 bytes| 159 bytes   |
| 159-238 bytes| 239 bytes  |

## Testing

- Unit tests in `padding_test.go` verify padding lengths match Signal-Android's test cases
- Round-trip test verifies `stripPadding(padMessage(content))` returns original content

## Lessons Learned

1. **Always check Signal-Android for message formatting** - Protocol details like padding are critical
2. **Server accepting a message (200 OK) doesn't mean it's valid** - Recipients still need to decrypt and parse
3. **Retry receipt loops indicate message format issues** - Recipients receive and can identify sender, but can't use the content
