package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/yurii-bondar/pgman/pool"
	"github.com/yurii-bondar/pgman/web"
)

// sseInterval is how often each open browser tab's own goroutine re-reads
// Stats()/sessions/events and re-renders. Every tab polls independently —
// there's no central broker/subscriber registry: Stats() is already a
// cheap, lock-brief snapshot (see pool.Pool.Stats), so N tabs each reading
// it a few times a second is simpler than fan-out plumbing for the same
// visible result, and it can't touch the hot Acquire/Release path either way.
const sseInterval = 500 * time.Millisecond

// poolDrainTimeout bounds how long a resize/remove waits for a pool's
// in-flight connections to finish naturally before giving up and just
// logging it — the registry mutation itself (what routing and the stats
// table see) already happened synchronously before this runs.
const poolDrainTimeout = 10 * time.Second

func poolRows(pools map[string]*pool.Pool) []web.PoolRow {
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]web.PoolRow, 0, len(pools))
	for _, name := range names {
		s := pools[name].Stats()
		rows = append(rows, web.PoolRow{
			Name:           name,
			Limit:          s.Limit,
			InUse:          s.InUse,
			Idle:           s.Idle,
			AcquireTotal:   s.WaitCount,
			AcquireSeconds: s.WaitTime.Seconds(),
			Discards:       s.Discards,
			DialErrors:     s.DialErrors,
		})
	}
	return rows
}

func sessionRows() []web.SessionRow {
	now := time.Now()
	infos := listSessions()

	rows := make([]web.SessionRow, 0, len(infos))
	for _, info := range infos {
		row := web.SessionRow{
			PID:          info.PID,
			User:         info.User,
			Database:     info.Database,
			Active:       info.Active,
			ConnectedFor: now.Sub(info.ConnectedAt).Round(time.Second).String(),
		}
		if info.Active {
			row.TxFor = now.Sub(info.TxStartedAt).Round(time.Second).String()
		}
		rows = append(rows, row)
	}
	return rows
}

func eventRows(log *EventLog) []web.EventRow {
	events := log.Recent()
	rows := make([]web.EventRow, 0, len(events))
	for _, e := range events {
		rows = append(rows, web.EventRow{
			Time: e.Time.Format("15:04:05"),
			Pool: e.Pool,
			Kind: e.Kind,
			Err:  e.Err,
		})
	}
	return rows
}

func manageRows(registry *PoolRegistry) []web.ManageRow {
	configs := registry.Configs()
	names := make([]string, 0, len(configs))
	for name := range configs {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]web.ManageRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, web.ManageRow{Name: name, Limit: configs[name].Limit})
	}
	return rows
}

func indexHandler(registry *PoolRegistry, eventLog *EventLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := web.Page(poolRows(registry.Pools()), sessionRows(), eventRows(eventLog), manageRows(registry))
		if err := page.Render(r.Context(), w); err != nil {
			slog.Warn("ui: render page", "err", err)
		}
	}
}

// sseHandler streams three htmx SSE events — "pools", "sessions", "events"
// — each targeting its own div. Closing the browser tab cancels
// r.Context(); the select below sees that and the goroutine returns,
// exactly the lifecycle DEV_PLAN calls for: no explicit unsubscribe
// needed, no goroutine leak. This never renders ManagePanel — the
// management controls live outside this refresh cycle on purpose (see
// ManagePanel's own doc comment: an in-progress resize edit must not be
// reset by a tick landing mid-keystroke).
func sseHandler(registry *PoolRegistry, eventLog *EventLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ticker := time.NewTicker(sseInterval)
		defer ticker.Stop()

		writeEvent := func(name string, c templ.Component) error {
			var buf strings.Builder
			if err := c.Render(r.Context(), &buf); err != nil {
				return err
			}
			fmt.Fprintf(w, "event: %s\n", name)
			for _, line := range strings.Split(buf.String(), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n\n")
			return nil
		}

		for {
			if err := writeEvent("pools", web.PoolsTable(poolRows(registry.Pools()))); err != nil {
				slog.Debug("ui: sse render pools", "err", err)
				return
			}
			if err := writeEvent("sessions", web.SessionsTable(sessionRows())); err != nil {
				slog.Debug("ui: sse render sessions", "err", err)
				return
			}
			if err := writeEvent("events", web.RecentEvents(eventRows(eventLog))); err != nil {
				slog.Debug("ui: sse render events", "err", err)
				return
			}
			flusher.Flush()

			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}
}

func renderManagePanel(w http.ResponseWriter, r *http.Request, registry *PoolRegistry, message string, isError bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := web.ManagePanel(manageRows(registry), message, isError).Render(r.Context(), w); err != nil {
		slog.Warn("ui: render manage panel", "err", err)
	}
}

// drainInBackground runs a pool's Close after it's already been swapped out
// of (or removed from) the registry — the visible effect (routing, Stats,
// the live table) is immediate; this just lets in-flight transactions
// finish and logs anything that didn't within poolDrainTimeout.
func drainInBackground(name string, p *pool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), poolDrainTimeout)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		slog.Warn("ui: drain pool", "pool", name, "err", err)
	}
}

func addPoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			renderManagePanel(w, r, registry, "parse form: "+err.Error(), true)
			return
		}
		limit, err := strconv.Atoi(r.FormValue("limit"))
		if err != nil {
			renderManagePanel(w, r, registry, "invalid limit: "+err.Error(), true)
			return
		}
		name := r.FormValue("name")
		cfg := PoolConfig{
			BackendDSN:  r.FormValue("backend_dsn"),
			BackendAddr: r.FormValue("backend_addr"),
			Limit:       limit,
		}
		if err := registry.Add(name, cfg); err != nil {
			renderManagePanel(w, r, registry, err.Error(), true)
			return
		}
		slog.Info("ui: pool added", "pool", name, "limit", limit)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q added.", name), false)
	}
}

func resizePoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			renderManagePanel(w, r, registry, "parse form: "+err.Error(), true)
			return
		}
		limit, err := strconv.Atoi(r.FormValue("limit"))
		if err != nil {
			renderManagePanel(w, r, registry, "invalid limit: "+err.Error(), true)
			return
		}
		old, err := registry.Resize(name, limit)
		if err != nil {
			renderManagePanel(w, r, registry, err.Error(), true)
			return
		}
		go drainInBackground(name, old)
		slog.Info("ui: pool resized", "pool", name, "limit", limit)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q resized to %d — old connections draining in background.", name, limit), false)
	}
}

func removePoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		old, err := registry.Remove(name)
		if err != nil {
			renderManagePanel(w, r, registry, err.Error(), true)
			return
		}
		go drainInBackground(name, old)
		slog.Info("ui: pool removed", "pool", name)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q removed — active sessions draining in background.", name), false)
	}
}

// pausePoolHandler implements PgBouncer's PAUSE: parks new Acquires
// until Resume. In-flight transactions finish normally.
func pausePoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		p, ok := registry.Get(name)
		if !ok {
			renderManagePanel(w, r, registry, fmt.Sprintf("pool %q not found", name), true)
			return
		}
		p.Pause()
		slog.Info("ui: pool paused", "pool", name)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q paused — new queries wait; in-flight finish.", name), false)
	}
}

// resumePoolHandler implements PgBouncer's RESUME: wakes every parked
// Acquire in one broadcast.
func resumePoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		p, ok := registry.Get(name)
		if !ok {
			renderManagePanel(w, r, registry, fmt.Sprintf("pool %q not found", name), true)
			return
		}
		p.Resume()
		slog.Info("ui: pool resumed", "pool", name)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q resumed.", name), false)
	}
}

// reconnectPoolHandler implements PgBouncer's RECONNECT: drains all
// idle immediately and marks in-flight to be dropped on release. Used
// after DNS flip, RDS failover, credential rotation.
func reconnectPoolHandler(registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		p, ok := registry.Get(name)
		if !ok {
			renderManagePanel(w, r, registry, fmt.Sprintf("pool %q not found", name), true)
			return
		}
		dropped := p.Reconnect()
		slog.Info("ui: pool reconnected", "pool", name, "idle_dropped", dropped)
		renderManagePanel(w, r, registry, fmt.Sprintf("pool %q reconnect issued: %d idle dropped, in-flight will refresh on release.", name, dropped), false)
	}
}

// cancelSessionHandler fires the same real CancelRequest a client's own
// Ctrl+C would, but from the admin UI. hx-swap="none" on the client side —
// the session table already refreshes every sseInterval, so the button
// doesn't need its own response rendered; the next tick shows the result.
func cancelSessionHandler(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.ParseUint(r.PathValue("pid"), 10, 32)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}
	if err := cancelSession(uint32(pid)); err != nil {
		slog.Warn("ui: cancel session failed", "pid", pid, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("ui: session cancelled", "pid", pid)
	w.WriteHeader(http.StatusNoContent)
}

// reloadHandler re-reads the YAML config and reports how it differs from
// what's actually running right now (the live registry, which may already
// have drifted from the on-disk file via the management panel above) —
// without applying it. Bulk-applying arbitrary config changes (a pool's
// DSN, say) needs the same drain care as a single resize, multiplied
// across every entry; a manual, one-at-a-time apply keeps that scoped.
func reloadHandler(configPath string, registry *PoolRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		cfg, err := loadConfig(configPath)
		if err != nil {
			if err := web.ReloadResult([]string{"config invalid, not applied:", err.Error()}, true).Render(r.Context(), w); err != nil {
				slog.Warn("ui: render reload result", "err", err)
			}
			return
		}

		current := registry.Names()
		currentSet := make(map[string]bool, len(current))
		for _, name := range current {
			currentSet[name] = true
		}
		fileSet := make(map[string]bool, len(cfg.Pools))
		for name := range cfg.Pools {
			fileSet[name] = true
		}

		var added, removed []string
		for name := range cfg.Pools {
			if !currentSet[name] {
				added = append(added, name)
			}
		}
		for _, name := range current {
			if !fileSet[name] {
				removed = append(removed, name)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)

		lines := []string{
			"config valid.",
			fmt.Sprintf("in file but not running: %v", added),
			fmt.Sprintf("running but not in file: %v", removed),
			"not applied automatically — use the pool controls above, or restart the process.",
		}
		if err := web.ReloadResult(lines, false).Render(r.Context(), w); err != nil {
			slog.Warn("ui: render reload result", "err", err)
		}
	}
}
