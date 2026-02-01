package signalservice

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
)

//go:embed signal_ca.pem
var signalCAPEM []byte

// TLSConfig returns a *tls.Config that trusts Signal's self-signed CA.
// Signal uses its own CA ("Signal Messenger, LLC") extracted from the
// Android app's whisper.store keystore.
func TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(signalCAPEM)
	return &tls.Config{
		RootCAs: pool,
	}
}
