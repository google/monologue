package interval

import (
	"testing"
	"time"
)

func TestRandomInstant(t *testing.T) {
	tests := []struct {
		desc     string
		iv       *Interval
		wantZero bool
	}{
		{
			desc:     "nil",
			iv:       nil,
			wantZero: true,
		},
		{
			desc: "day",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 26, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			desc: "second",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 1, 0, time.UTC),
			},
		},
		{
			desc: "nanosecond",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
			},
		},
		{
			desc: "equal",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "end just before start",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "end before start",
			iv: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 24, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := test.iv.RandomInstant()

			if test.wantZero {
				if !got.IsZero() {
					t.Fatalf("%v.RandomInstant() = %s, want %s (the zero time)", test.iv, got, time.Time{})
				}
				return
			}

			if got.Before(test.iv.Start) || !test.iv.End.After(got) {
				t.Fatalf("%v.RandomInstant() = %s, want between [%s, %s)", test.iv, got, test.iv.Start, test.iv.End)
			}
		})
	}
}
