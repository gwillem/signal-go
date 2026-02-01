package provisioncrypto

import "testing"

func TestVerifyMACCorrect(t *testing.T) {
	key := []byte("test-key-32-bytes-long-aaaaaaaaa")
	data := []byte("hello world")

	mac := ComputeMAC(key, data)
	if err := VerifyMAC(key, data, mac); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMACTampered(t *testing.T) {
	key := []byte("test-key-32-bytes-long-aaaaaaaaa")
	data := []byte("hello world")
	mac := ComputeMAC(key, data)

	// Tamper with MAC.
	mac[0] ^= 0xff
	if err := VerifyMAC(key, data, mac); err == nil {
		t.Fatal("expected error for tampered MAC")
	}

	// Correct MAC but tampered data.
	mac = ComputeMAC(key, data)
	if err := VerifyMAC(key, []byte("goodbye world"), mac); err == nil {
		t.Fatal("expected error for tampered data")
	}
}
