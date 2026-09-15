// Package main — safe subset config reload for SIGHUP / API triggers.
//
// SIGHUP is the standard Unix-daemon convention for "re-read config
// without restarting" — systemd, k8s configmap-reloader, and every DBA
// muscle memory expect it to work. PgBouncer, nginx, HAProxy all speak
// this dialect.
//
// What SIGHUP applies here:
//
//   - new pools present in the file but not in the registry — added
//   - pools present in the registry but not in the file — removed
//   - pools whose configuration changed — replaced at the new settings
//     (limit, backend_dsn, backend_addr, pool_mode, aliases,
//     backend_users, per-pool lifecycle overrides)
//
// In all three cases the pools being displaced are drained in the
// background, so sessions already routed to them finish their
// transactions against the backend they started on. Only new sessions
// see the new configuration — the same contract the admin API's resize
// and remove have always had.
//
// Reconfiguration used to be excluded on the grounds that a hot swap
// needs drain care, which was true but left the operator worse off:
// the only way to change a limit or repoint a DSN was a process
// restart, which drops every session rather than the ones the change
// affects. The drain care turned out to be the same three lines Resize
// already had.
//
// What SIGHUP still does NOT do: listener, TLS and auth wiring. Those
// are bound to sockets and credentials established at startup, so
// changing them needs a full restart.
//
// One consequence worth knowing: the file is the source of truth. A
// limit changed through the admin UI and not written back to the YAML
// is reverted by the next reload, because the alternative — treating a
// live value as authoritative — means nobody can tell what a restart
// would bring up.
package main

import (
	"fmt"
	"sort"
)

// ReloadResult reports what applyConfigReload did to the live registry.
// Populated even on partial failure (some pools added, one failed to
// add — the error and the caller-consumable diff both matter).
type ReloadResult struct {
	Added        []string // pools present in file but not in registry — created
	Removed      []string // pools present in registry but not in file — removed
	Reconfigured []string // pools present in both, with a changed config — replaced
	Unchanged    []string // pools present in both with an identical config — left alone
}

// applyConfigReload re-reads configPath and reconciles the live pool
// registry against it — adds missing pools, removes surplus ones, and
// replaces the ones whose configuration changed.
//
// Errors during add/reconfigure/remove are collected into a summary but
// do not abort the whole reload: k8s configmap-reloader flips one file
// with many changes, and a single mid-list failure shouldn't blackhole
// the rest of the delta.
func applyConfigReload(configPath string, registry *PoolRegistry) (ReloadResult, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return ReloadResult{}, fmt.Errorf("reload: parse %s: %w", configPath, err)
	}

	// Pool names, not registry keys: a pool split by backend_users has
	// one entry per identity, and diffing those against the file's
	// `pools:` map would report every per-user pool as surplus.
	currentNames := registry.PoolNames()
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
			old, changed, err := registry.Reconfigure(name, cfg.Pools[name])
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("reconfigure %q: %w", name, err))
			case changed:
				result.Reconfigured = append(result.Reconfigured, name)
				drainPoolsInBackground(name, old)
			default:
				result.Unchanged = append(result.Unchanged, name)
			}
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
