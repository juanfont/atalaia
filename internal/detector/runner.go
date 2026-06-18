package detector

import (
	"context"
	"sync"
)

// Run scans the diff with every detector in parallel and returns the
// merged finding list plus a per-detector error map. A detector error
// never fails the whole request; the API layer surfaces the map in the
// per-request stats.
//
// sem bounds how many detector scans run concurrently across all
// in-flight requests. Pass nil for unbounded. The cap matters because
// subprocess detectors (trufflehog, kingfisher) are expensive to
// start: a burst of concurrent /check calls would otherwise spawn one
// process per detector per request all at once, saturate the host, and
// blow the per-request scan timeout. With the semaphore the scans
// queue instead, so each one gets a slot on an unsaturated box and
// finishes in milliseconds.
func Run(ctx context.Context, diff []byte, dets []Detector, sem chan struct{}) ([]Finding, map[string]error) {
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

			if sem != nil {
				// Don't start a (possibly subprocess-spawning) scan if
				// the request already gave up while we waited in line.
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

			fs, err := d.Scan(ctx, diff)
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
