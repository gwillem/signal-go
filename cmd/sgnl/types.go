package main

import (
	"fmt"
	"strings"
)

// optionalBool is a tri-state boolean that can be unset, true, or false.
// It parses "true" or "false" string values from command line flags.
type optionalBool struct {
	value *bool
}

func (o *optionalBool) UnmarshalFlag(val string) error {
	switch strings.ToLower(val) {
	case "true", "1", "yes":
		v := true
		o.value = &v
	case "false", "0", "no":
		v := false
		o.value = &v
	default:
		return fmt.Errorf("invalid boolean value: %q (use true or false)", val)
	}
	return nil
}

func (o *optionalBool) MarshalFlag() (string, error) {
	if o.value == nil {
		return "", nil
	}
	if *o.value {
		return "true", nil
	}
	return "false", nil
}
