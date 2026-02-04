package main

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"

	client "github.com/gwillem/signal-go"
)

type safetyNumberCommand struct {
	Args struct {
		TheirUUID string `positional-arg-name:"their-uuid" required:"true" description:"The other party's ACI UUID"`
	} `positional-args:"yes"`
}

func (cmd *safetyNumberCommand) Execute(args []string) error {
	c := client.NewClient(clientOpts()...)
	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	// Get our identity key
	ourIdentity, err := c.IdentityKey()
	if err != nil {
		return fmt.Errorf("get our identity key: %w", err)
	}

	// Get their identity key from our store
	theirIdentity, err := c.GetIdentityKey(cmd.Args.TheirUUID)
	if err != nil {
		return fmt.Errorf("get their identity key: %w", err)
	}

	// Get UUIDs
	ourUUID := c.ACI()
	theirUUID := cmd.Args.TheirUUID

	fmt.Printf("Our ACI:    %s\n", ourUUID)
	fmt.Printf("Their ACI:  %s\n", theirUUID)
	fmt.Printf("Our key:    %x\n", ourIdentity)
	fmt.Printf("Their key:  %x\n", theirIdentity)
	fmt.Println()

	// Compute safety number
	safetyNumber := computeSafetyNumber(ourUUID, ourIdentity, theirUUID, theirIdentity)
	fmt.Printf("Safety Number:\n%s\n", formatSafetyNumber(safetyNumber))

	return nil
}

// computeSafetyNumber computes the Signal safety number (fingerprint).
// Based on Signal's NumericFingerprintGenerator.
func computeSafetyNumber(id1 string, key1 []byte, id2 string, key2 []byte) string {
	// Determine order: lower ID first
	var firstID, secondID string
	var firstKey, secondKey []byte

	if id1 < id2 {
		firstID, firstKey = id1, key1
		secondID, secondKey = id2, key2
	} else {
		firstID, firstKey = id2, key2
		secondID, secondKey = id1, key1
	}

	// Compute fingerprint for each party
	fp1 := computeFingerprint(firstID, firstKey)
	fp2 := computeFingerprint(secondID, secondKey)

	return fp1 + fp2
}

// computeFingerprint computes a 30-digit fingerprint for one party.
func computeFingerprint(id string, key []byte) string {
	// Version byte
	version := []byte{0x00, 0x00}

	// 5200 iterations of SHA-512
	hash := sha512.New()
	hash.Write(version)
	hash.Write(key)
	hash.Write([]byte(id))
	digest := hash.Sum(nil)

	for i := 0; i < 5199; i++ {
		hash.Reset()
		hash.Write(digest)
		hash.Write(key)
		digest = hash.Sum(nil)
	}

	// Convert first 30 bytes to 30 digits (5 groups of 6 digits)
	var result strings.Builder
	for i := 0; i < 6; i++ {
		// Take 5 bytes and convert to a number mod 100000
		chunk := digest[i*5 : i*5+5]
		// Pad to 8 bytes for uint64
		padded := make([]byte, 8)
		copy(padded[3:], chunk)
		num := binary.BigEndian.Uint64(padded) % 100000
		result.WriteString(fmt.Sprintf("%05d", num))
	}

	return result.String()
}

// formatSafetyNumber formats the 60-digit number into groups.
func formatSafetyNumber(sn string) string {
	var lines []string
	for i := 0; i < len(sn); i += 20 {
		end := i + 20
		if end > len(sn) {
			end = len(sn)
		}
		// Split into groups of 5
		line := sn[i:end]
		var groups []string
		for j := 0; j < len(line); j += 5 {
			gend := j + 5
			if gend > len(line) {
				gend = len(line)
			}
			groups = append(groups, line[j:gend])
		}
		lines = append(lines, strings.Join(groups, " "))
	}
	return strings.Join(lines, "\n")
}
