// Package main — safe subset config reload for SIGHUP / API triggers.
//
// SIGHUP is the standard Unix-daemon convention for "re-read config
// without restarting" — systemd, k8s configmap-reloader, and every DBA
// muscle memory expect it to work. PgBouncer, nginx, HAProxy all speak
// this dialect.
//
// What SIGHUP applies here (the "safe subset"):
//
//   - new pools present in the file but not in the registry — added
//   - pools present in the registry but not in the file — removed
//     (with graceful background drain of their in-flight sessions)
//
// What SIGHUP intentionally does NOT do:
//
//   - resize an existing pool (a hot resize needs the same drain care
//     as a remove — do it through the /pools/{name}/resize endpoint)
//   - swap a pool's backend_dsn (would silently redirect live sessions)
//   - change listener/TLS/auth wiring (those need a full restart)
//
// The rationale mirrors PgBouncer: SIGHUP is for operational safety,
// not for arbitrary reconfiguration. Anything that could interrupt
// active traffic must stay opt-in through the admin plane.
package main

import (
	"fmt"
	"sort"
)

// ReloadResult reports what applyConfigReload did to the live registry.
// Populated even on partial failure (some pools added, one failed to
// add — the error and the caller-consumable diff both matter).
type ReloadResult struct {
	Added     []string // pools present in file but not in registry — created
	Removed   []string // pools present in registry but not in file — removed
	Unchanged []string // pools present in both (config-diff not applied — see doc comment)
}

// applyConfigReload re-reads configPath and reconciles the live pool
// registry against it — adds missing pools, removes surplus ones,
// leaves existing pools untouched (see file-level doc for rationale).
//
// Errors during add/remove are collected into a summary but do not
// abort the whole reload: k8s configmap-reloader flips one file with
// many changes, and a single mid-list failure shouldn't blackhole the
// rest of the delta.
func applyConfigReload(configPath string, registry *PoolRegistry) (ReloadResult, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return ReloadResult{}, fmt.Errorf("reload: parse %s: %w", configPath, err)
	}

	currentNames := registry.Names()
	currentSet := make(map[string]bool, len(currentNames))
	for _, n := range currentNames {
		currentSet[n] = true
	}

	var result ReloadResult
	var errs []error

	// Add new pools first — if an add fails, the surplus ones we're
	// about to remove might still be needed by clients.
	fileNames := make([]string, 0, len(cfg.Pools))
	for name := range cfg.Pools {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		if currentSet[name] {
			result.Unchanged = append(result.Unchanged, name)
			continue
		}
		if err := registry.Add(name, cfg.Pools[name]); err != nil {
			errs = append(errs, fmt.Errorf("add %q: %w", name, err))
			continue
		}
		result.Added = append(result.Added, name)
	}

	// Then remove pools no longer in the file. Removed pools are
	// drained in a background goroutine so SIGHUP handler doesn't
	// block on in-flight tx that might take seconds.
	for _, name := range currentNames {
		if _, still := cfg.Pools[name]; still {
			continue
		}
		old, err := registry.Remove(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("remove %q: %w", name, err))
			continue
		}
		result.Removed = append(result.Removed, name)
		drainPoolsInBackground(name, old)
	}

	if len(errs) > 0 {
		// Return a combined error but ALSO the partial result — the
		// caller (SIGHUP handler / HTTP endpoint) can still log what
		// went through.
		return result, fmt.Errorf("reload: %d error(s): %v", len(errs), errs)
	}
	return result, nil
}
