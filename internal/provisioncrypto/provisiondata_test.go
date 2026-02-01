package provisioncrypto

import (
	"testing"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

func TestParseProvisionData(t *testing.T) {
	number := "+15551234567"
	code := "provision-code-123"
	aci := "aci-uuid"
	pni := "pni-uuid"
	version := uint32(1)
	aep := "account-entropy-pool"

	msg := &proto.ProvisionMessage{
		Number:                &number,
		ProvisioningCode:      &code,
		Aci:                   &aci,
		Pni:                   &pni,
		ProvisioningVersion:   &version,
		AccountEntropyPool:    &aep,
		AciIdentityKeyPublic:  []byte{0x05, 0x01, 0x02},
		AciIdentityKeyPrivate: []byte{0x03, 0x04},
		PniIdentityKeyPublic:  []byte{0x05, 0x05, 0x06},
		PniIdentityKeyPrivate: []byte{0x07, 0x08},
		ProfileKey:            []byte{0xde, 0xad, 0xbe, 0xef},
		MasterKey:             []byte{0xca, 0xfe},
	}

	data, err := pb.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	pd, err := ParseProvisionData(data)
	if err != nil {
		t.Fatal(err)
	}

	if pd.Number != number {
		t.Fatalf("number: got %q, want %q", pd.Number, number)
	}
	if pd.ProvisioningCode != code {
		t.Fatalf("code: got %q, want %q", pd.ProvisioningCode, code)
	}
	if pd.ACI != aci {
		t.Fatalf("aci: got %q, want %q", pd.ACI, aci)
	}
	if pd.PNI != pni {
		t.Fatalf("pni: got %q, want %q", pd.PNI, pni)
	}
	if pd.AccountEntropyPool != aep {
		t.Fatalf("aep: got %q, want %q", pd.AccountEntropyPool, aep)
	}
}

func TestParseProvisionDataMissingCode(t *testing.T) {
	number := "+15551234567"
	msg := &proto.ProvisionMessage{
		Number:                &number,
		AciIdentityKeyPublic:  []byte{0x05, 0x01},
		AciIdentityKeyPrivate: []byte{0x02},
	}

	data, err := pb.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseProvisionData(data)
	if err == nil {
		t.Fatal("expected error for missing provisioning code")
	}
}

func TestParseProvisionDataMissingIdentityKeys(t *testing.T) {
	number := "+15551234567"
	code := "abc"
	msg := &proto.ProvisionMessage{
		Number:           &number,
		ProvisioningCode: &code,
	}

	data, err := pb.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseProvisionData(data)
	if err == nil {
		t.Fatal("expected error for missing identity keys")
	}
}
