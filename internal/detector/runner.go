package detector

import (
	"context"
	"sync"
	"time"
)

// Run scans the diff with every detector in parallel and returns the
// merged finding list plus a per-detector error map. A detector error
// never fails the whole request; the API layer surfaces the map in the
// per-request stats and decides the HTTP status.
//
// sem bounds how many subprocess detector scans run concurrently across
// all in-flight requests. Pass nil for unbounded. The cap matters
// because subprocess detectors (trufflehog, kingfisher) pay their full
// startup cost on every invocation: a burst of concurrent /check calls
// would otherwise spawn one process per detector per request all at
// once and saturate the host. In-process detectors (gitleaks) are
// exempt — they spawn nothing, so gating them only adds latency.
//
// scanTimeout bounds how long a single Scan may run, and the clock
// starts only once the detector holds its semaphore slot — time spent
// queued does NOT count against it. This is deliberate: charging queue
// wait to the scan deadline meant that under a burst, a request could
// be killed while still waiting in line, never having scanned anything,
// and report a false "clean". Queue wait is instead bounded by ctx
// (the caller's request/client deadline). Pass <= 0 to disable the
// per-scan timeout.
func Run(ctx context.Context, diff []byte, dets []Detector, sem chan struct{}, scanTimeout time.Duration) ([]Finding, map[string]error) {
	var (
		mu       sync.Mutex
		findings []Finding
		errs     = map[string]error{}
		wg       sync.WaitGroup
	)
	for _, d := range dets {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()

			if sem != nil && gated(d) {
				// Don't start a subprocess-spawning scan if the request
				// already gave up while we waited in line.
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					mu.Lock()
					errs[d.Name()] = ctx.Err()
					mu.Unlock()
					return
				}
			}

			// Per-scan deadline starts here, after the slot is held, so
			// queue wait is never charged against the scan budget.
			scanCtx := ctx
			if scanTimeout > 0 {
				var cancel func()
				scanCtx, cancel = context.WithTimeout(ctx, scanTimeout)
				defer cancel()
			}

			fs, err := d.Scan(scanCtx, diff)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[d.Name()] = err
				return
			}
			findings = append(findings, fs...)
		}(d)
	}
	wg.Wait()
	return findings, errs
}
