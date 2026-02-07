package signalservice

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gwillem/signal-go/internal/proto"
)

// dumpEnvelope writes raw envelope bytes to debugDir for offline inspection.
// No-op if debugDir is empty.
func dumpEnvelope(debugDir string, data []byte, env *proto.Envelope, logger *log.Logger) {
	if debugDir == "" {
		return
	}

	typeName := env.GetType().String()
	sender := env.GetSourceServiceId()
	if sender == "" {
		sender = "sealed"
	} else if len(sender) > 8 {
		sender = sender[:8]
	}
	device := env.GetSourceDevice()
	ts := env.GetServerTimestamp()
	if ts == 0 {
		ts = env.GetTimestamp()
	}

	if err := os.MkdirAll(debugDir, 0o755); err != nil {
		logf(logger, "dump: mkdir %s: %v", debugDir, err)
		return
	}

	name := fmt.Sprintf("%d_%s_%s_%d.bin", ts, typeName, sender, device)
	path := filepath.Join(debugDir, name)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		logf(logger, "dump: write %s: %v", path, err)
		return
	}
	logf(logger, "dump: wrote %s (%d bytes)", path, len(data))
}

// loadDump reads a dumped envelope file (for use in tests).
func loadDump(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// dumpContent writes Content protobuf bytes to debugDir for comparison.
// direction is "send" or "recv". No-op if debugDir is empty.
func dumpContent(debugDir string, direction string, recipient string, timestamp uint64, data []byte, logger *log.Logger) {
	if debugDir == "" {
		return
	}

	if err := os.MkdirAll(debugDir, 0o755); err != nil {
		logf(logger, "dump: mkdir %s: %v", debugDir, err)
		return
	}

	// Shorten recipient for filename.
	short := recipient
	if len(short) > 8 {
		short = short[:8]
	}

	name := fmt.Sprintf("%d_%s_content_%s.bin", timestamp, direction, short)
	path := filepath.Join(debugDir, name)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		logf(logger, "dump: write %s: %v", path, err)
		return
	}
	logf(logger, "dump: wrote %s (%d bytes)", path, len(data))
}
