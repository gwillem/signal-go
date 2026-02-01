package provisioncrypto

import (
	"fmt"

	"github.com/gwillem/signal-go/pkg/proto"
	pb "google.golang.org/protobuf/proto"
)

// ProvisionData holds the parsed fields from a decrypted ProvisionMessage.
type ProvisionData struct {
	Number              string
	ProvisioningCode    string
	ACI                 string
	PNI                 string
	ProvisioningVersion uint32
	AccountEntropyPool  string

	ACIIdentityKeyPublic  []byte
	ACIIdentityKeyPrivate []byte
	PNIIdentityKeyPublic  []byte
	PNIIdentityKeyPrivate []byte
	ProfileKey            []byte
	MasterKey             []byte
	EphemeralBackupKey    []byte
	MediaRootBackupKey    []byte
}

// ParseProvisionData unmarshals decrypted bytes into ProvisionData, validating required fields.
func ParseProvisionData(data []byte) (*ProvisionData, error) {
	msg := new(proto.ProvisionMessage)
	if err := pb.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("provisiondata: unmarshal: %w", err)
	}

	if msg.GetProvisioningCode() == "" {
		return nil, fmt.Errorf("provisiondata: missing provisioning code")
	}
	if len(msg.GetAciIdentityKeyPublic()) == 0 || len(msg.GetAciIdentityKeyPrivate()) == 0 {
		return nil, fmt.Errorf("provisiondata: missing ACI identity keys")
	}

	return &ProvisionData{
		Number:                msg.GetNumber(),
		ProvisioningCode:      msg.GetProvisioningCode(),
		ACI:                   msg.GetAci(),
		PNI:                   msg.GetPni(),
		ProvisioningVersion:   msg.GetProvisioningVersion(),
		AccountEntropyPool:    msg.GetAccountEntropyPool(),
		ACIIdentityKeyPublic:  msg.GetAciIdentityKeyPublic(),
		ACIIdentityKeyPrivate: msg.GetAciIdentityKeyPrivate(),
		PNIIdentityKeyPublic:  msg.GetPniIdentityKeyPublic(),
		PNIIdentityKeyPrivate: msg.GetPniIdentityKeyPrivate(),
		ProfileKey:            msg.GetProfileKey(),
		MasterKey:             msg.GetMasterKey(),
		EphemeralBackupKey:    msg.GetEphemeralBackupKey(),
		MediaRootBackupKey:    msg.GetMediaRootBackupKey(),
	}, nil
}
