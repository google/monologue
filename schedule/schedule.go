package schedule

import (
	"context"
	"time"
)

// Every will call f periodically.
func Every(ctx context.Context, period time.Duration, f func(context.Context)) {
	if ctx.Err() != nil {
		return
	}

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// TODO(katjoyce): Work out when and where to add context timeouts.
			f(ctx)
		case <-ctx.Done():
			return
		}
	}
}
