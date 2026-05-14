package detector

import (
	"context"
	"sync"
)

// Run scans the diff with every detector in parallel and returns the
// merged finding list plus a per-detector error map. A detector error
// never fails the whole request; the API layer surfaces the map in the
// per-request stats.
func Run(ctx context.Context, diff []byte, dets []Detector) ([]Finding, map[string]error) {
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
