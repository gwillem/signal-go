package signalservice

import "testing"

// TestPadMessage verifies padding matches Signal-Android's PushTransportDetails.
// Reference: Signal-Android/lib/libsignal-service/src/test/java/org/whispersystems/signalservice/api/push/PushTransportDetailsTest.kt
func TestPadMessage(t *testing.T) {
	// Messages 0-78 bytes should pad to 79 bytes
	for i := 0; i < 79; i++ {
		msg := make([]byte, i)
		padded := padMessage(msg)
		if len(padded) != 79 {
			t.Errorf("message len %d: got padded len %d, want 79", i, len(padded))
		}
		// Verify terminator
		if padded[i] != 0x80 {
			t.Errorf("message len %d: terminator byte is %#x, want 0x80", i, padded[i])
		}
		// Verify remaining bytes are zero
		for j := i + 1; j < len(padded); j++ {
			if padded[j] != 0x00 {
				t.Errorf("message len %d: byte %d is %#x, want 0x00", i, j, padded[j])
			}
		}
	}

	// Messages 79-158 bytes should pad to 159 bytes
	for i := 79; i < 159; i++ {
		msg := make([]byte, i)
		padded := padMessage(msg)
		if len(padded) != 159 {
			t.Errorf("message len %d: got padded len %d, want 159", i, len(padded))
		}
	}

	// Messages 159-238 bytes should pad to 239 bytes
	for i := 159; i < 239; i++ {
		msg := make([]byte, i)
		padded := padMessage(msg)
		if len(padded) != 239 {
			t.Errorf("message len %d: got padded len %d, want 239", i, len(padded))
		}
	}
}

// TestStripPadding verifies that stripPadding correctly reverses padMessage.
func TestStripPadding(t *testing.T) {
	testCases := []int{0, 1, 10, 50, 78, 79, 100, 158, 159, 200, 238, 239}

	for _, size := range testCases {
		original := make([]byte, size)
		for i := range original {
			original[i] = byte(i % 256)
		}

		padded := padMessage(original)
		stripped := stripPadding(padded)

		if len(stripped) != len(original) {
			t.Errorf("size %d: stripped len %d, want %d", size, len(stripped), len(original))
			continue
		}

		for i := range original {
			if stripped[i] != original[i] {
				t.Errorf("size %d: byte %d differs: got %#x, want %#x", size, i, stripped[i], original[i])
				break
			}
		}
	}
}
