// Two guards with no caller-side seam: the retry clock's default and
// the snapshot decoder's exhaustiveness. Both are reachable only from
// inside the package, and both fail silently if they are wrong — a
// retry ladder that never waits is a burst, and a decode target the
// switch does not know would leave the caller's value at its zero.

package gh

import (
	"testing"
	"time"
)

// TestSleepDefaultsToTheRealClock pins the documented default: a
// client that never set Sleep still waits between attempts, so the
// ladder in the comment is the ladder in the code.
func TestSleepDefaultsToTheRealClock(t *testing.T) {
	t.Parallel()

	const wait = 2 * time.Millisecond

	c := &Client{}

	start := time.Now()
	c.sleep(wait)

	if elapsed := time.Since(start); elapsed < wait {
		t.Fatalf("sleep(%v) returned after %v — a nil Sleep must be the real clock", wait, elapsed)
	}
}

// TestDecodeIntoRefusesAnUnknownTarget: the type switch is the
// snapshot layer's whole decode surface, so a target it does not know
// must refuse. Returning nil would hand the caller a zero value that
// looks exactly like a recorded empty.
func TestDecodeIntoRefusesAnUnknownTarget(t *testing.T) {
	t.Parallel()

	var target float64

	if err := decodeInto([]byte(`1.5`), &target); err == nil {
		t.Fatalf("decodeInto accepted an unsupported target and left it at %v", target)
	}
}
