package assert

import (
	"math"
	"testing"
)

// intSize holds a count past the report's int at the int's limit
// rather than wrapping it negative.
func TestIntSizeClamps(t *testing.T) {
	t.Parallel()

	if got := intSize(math.MaxUint64); got != math.MaxInt {
		t.Fatalf("intSize(MaxUint64) = %d, want MaxInt", got)
	}

	if got := intSize(42); got != 42 {
		t.Fatalf("intSize(42) = %d", got)
	}
}
