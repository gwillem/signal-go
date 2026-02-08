package signalservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/store"
)

// CDSIAuthResponse holds the temporary CDSI credentials.
type CDSIAuthResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GetCDSIAuth fetches CDSI-specific auth credentials from the server.
func (s *Service) GetCDSIAuth(ctx context.Context) (*CDSIAuthResponse, error) {
	body, status, err := s.transport.Get(ctx, "/v2/directory/auth", &s.auth)
	if err != nil {
		return nil, fmt.Errorf("cdsi auth: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("cdsi auth: status %d: %s", status, body)
	}
	var resp CDSIAuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("cdsi auth: unmarshal: %w", err)
	}
	return &resp, nil
}

// LookupNumbers resolves E.164 phone numbers to service IDs via CDSI.
// Returns a map of e164 → service ID (ACI preferred, PNI as fallback).
// Numbers not on Signal are omitted. Results are saved to the contact store.
func (s *Service) LookupNumbers(
	ctx context.Context,
	numbers []string,
	asyncCtx *libsignal.TokioAsyncContext,
	connMgr *libsignal.ConnectionManager,
) (map[string]string, error) {
	if len(numbers) == 0 {
		return nil, nil
	}

	// Fetch CDSI auth credentials.
	auth, err := s.GetCDSIAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Build lookup request.
	req, err := libsignal.NewLookupRequest()
	if err != nil {
		return nil, fmt.Errorf("cdsi: new request: %w", err)
	}
	defer req.Destroy()

	for _, number := range numbers {
		if err := req.AddE164(number); err != nil {
			return nil, fmt.Errorf("cdsi: add e164 %q: %w", number, err)
		}
	}

	logf(s.logger, "cdsi: looking up %d numbers", len(numbers))

	// Perform CDSI lookup.
	results, err := libsignal.CDSILookup(asyncCtx, connMgr, auth.Username, auth.Password, req)
	if err != nil {
		return nil, fmt.Errorf("cdsi: lookup: %w", err)
	}

	logf(s.logger, "cdsi: got %d results", len(results))

	// Parse results and save to contact store.
	resolved := make(map[string]string, len(results))
	for _, r := range results {
		// Convert E.164 uint64 back to string (e.g. 31612345678 → "+31612345678").
		e164 := fmt.Sprintf("+%d", r.E164)

		aci, _ := uuid.FromBytes(r.ACI[:])
		pni, _ := uuid.FromBytes(r.PNI[:])

		logf(s.logger, "cdsi: %s → aci=%s pni=%s", e164, aci, pni)

		// Pick the best service ID: prefer ACI, fall back to PNI.
		// CDSI returns PNI-only when the account has "who can find me
		// by number" set to Nobody, but PNI is still a valid service ID
		// for sending. Signal API requires the "PNI:" prefix for PNI-based
		// endpoints (e.g. /v2/keys/PNI:uuid/1, /v1/messages/PNI:uuid).
		serviceID := aci.String()
		if aci == uuid.Nil {
			if pni == uuid.Nil {
				// Neither ACI nor PNI — number is not on Signal.
				continue
			}
			serviceID = "PNI:" + pni.String()
		}

		resolved[e164] = serviceID

		// Save to contact store for future lookups.
		if s.store != nil {
			if err := s.store.SaveContact(&store.Contact{
				ACI:    serviceID,
				Number: e164,
			}); err != nil {
				logf(s.logger, "cdsi: save contact %s: %v", e164, err)
			}
		}
	}

	return resolved, nil
}
