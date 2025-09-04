package certinfo

import (
	"fmt"

	"github.com/carlmjohnson/errutil"
)

// errs accumulates non-fatal errors across hosts/certs.
var errs errutil.Slice

// WriteErrors merges and prints accumulated errors; returns an exit code.
func WriteErrors(output string) error {
	if err := errs.Merge(); err != nil {
		if output != "none" {
			return fmt.Errorf("problem running certinfo: %+v", err)
		}
	}
	return nil
}

// PushError allows other packages to add non-fatal errors to the accumulator.
func PushError(err error) {
	errs.Push(err)
}
