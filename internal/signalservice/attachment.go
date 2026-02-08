package signalservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/signalcrypto"
)

// downloadAttachment downloads and decrypts an attachment from Signal's CDN.
func downloadAttachment(ctx context.Context, ptr *proto.AttachmentPointer, tlsConf *tls.Config) ([]byte, error) {
	if ptr == nil {
		return nil, fmt.Errorf("attachment: nil pointer")
	}

	key := ptr.GetKey()
	if len(key) != 64 {
		return nil, fmt.Errorf("attachment: invalid key length %d", len(key))
	}

	url, err := signalcrypto.AttachmentURL(ptr)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("attachment: create request: %w", err)
	}

	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("attachment: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment: download status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("attachment: read body: %w", err)
	}

	return signalcrypto.DecryptAttachment(data, key)
}
