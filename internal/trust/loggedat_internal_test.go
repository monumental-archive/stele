package trust

import (
	"strings"
	"testing"
	"time"
)

// TestVerifiedLoggedAt: the logged instant is the latest
// transparency-log observation, never another class's, and a
// verification holding none says so by name.
func TestVerifiedLoggedAt(t *testing.T) {
	t.Parallel()

	early := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	later := late.Add(time.Hour)

	tlog := func(at time.Time) ObservedInstant {
		return ObservedInstant{at: at, source: SourceTransparencyLog, log: "https://rekor.example"}
	}

	tests := []struct {
		name     string
		observed []ObservedInstant
		want     time.Time
		wantErr  string
	}{
		{name: "one log observation", observed: []ObservedInstant{tlog(early)}, want: early},
		{name: "the latest of two", observed: []ObservedInstant{tlog(late), tlog(early)}, want: late},
		{
			name: "other classes are not the log time",
			observed: []ObservedInstant{
				tlog(early),
				{at: later, source: SourceTimestampAuthority, log: "https://tsa.example"},
				{at: later, source: SourceCertificateTransparency, log: "ct"},
			},
			want: early,
		},
		{
			name:     "no log observation",
			observed: []ObservedInstant{{at: later, source: SourceCertificateTransparency, log: "ct"}},
			wantErr:  "no transparency log observed the signing",
		},
		{name: "nothing observed", wantErr: "no transparency log observed the signing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := (&Verified{Observed: tt.observed}).LoggedAt()

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoggedAt() error = %v, want %q", err, tt.wantErr)
				}

				return
			}

			if err != nil || !got.Equal(tt.want) {
				t.Fatalf("LoggedAt() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}
