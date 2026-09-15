package web

import (
	"context"
	"strings"
	"testing"
)

func TestPoolRowSaturated(t *testing.T) {
	cases := []struct {
		name string
		row  PoolRow
		want bool
	}{
		{"under limit", PoolRow{Limit: 2, InUse: 1}, false},
		{"at limit", PoolRow{Limit: 2, InUse: 2}, true},
		{"over limit (shouldn't happen, but defensive)", PoolRow{Limit: 2, InUse: 3}, true},
		{"zero limit never saturated", PoolRow{Limit: 0, InUse: 0}, false},
	}
	for _, c := range cases {
		if got := c.row.Saturated(); got != c.want {
			t.Errorf("%s: Saturated() = %v, want %v", c.name, got, c.want)
		}
	}
}

func renderString(t *testing.T, render func(w *strings.Builder) error) string {
	t.Helper()
	var buf strings.Builder
	if err := render(&buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func TestPoolsTableRendersRows(t *testing.T) {
	rows := []PoolRow{
		{Name: "shop", Limit: 2, InUse: 2, Idle: 0, AcquireTotal: 5, AcquireSeconds: 1.234, Discards: 1, DialErrors: 0},
	}
	out := renderString(t, func(w *strings.Builder) error {
		return PoolsTable(rows).Render(context.Background(), w)
	})
	for _, want := range []string{"shop", "2 / 2", "full", "1.234"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestPoolsTableEmpty(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return PoolsTable(nil).Render(context.Background(), w)
	})
	if !strings.Contains(out, "No pools configured") {
		t.Errorf("expected empty-state message, got:\n%s", out)
	}
}

func TestSessionsTableRendersActiveWithCancelButton(t *testing.T) {
	rows := []SessionRow{
		{PID: 42, User: "alice", Database: "db1", Active: true, ConnectedFor: "5s", TxFor: "1s"},
	}
	out := renderString(t, func(w *strings.Builder) error {
		return SessionsTable(rows).Render(context.Background(), w)
	})
	for _, want := range []string{"alice", "db1", "/sessions/42/cancel", "state-active"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestSessionsTableIdleHasNoCancelButton(t *testing.T) {
	rows := []SessionRow{
		{PID: 7, User: "bob", Database: "db1", Active: false, ConnectedFor: "10s"},
	}
	out := renderString(t, func(w *strings.Builder) error {
		return SessionsTable(rows).Render(context.Background(), w)
	})
	if strings.Contains(out, "/sessions/7/cancel") {
		t.Error("an idle session must not render a Cancel button")
	}
	if !strings.Contains(out, "state-idle") {
		t.Error("expected idle state badge")
	}
}

func TestSessionsTableEmpty(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return SessionsTable(nil).Render(context.Background(), w)
	})
	if !strings.Contains(out, "No active sessions") {
		t.Errorf("expected empty-state message, got:\n%s", out)
	}
}

func TestRecentEventsRendersRows(t *testing.T) {
	rows := []EventRow{
		{Time: "12:00:00", Pool: "shop", Kind: "discard", Err: ""},
	}
	out := renderString(t, func(w *strings.Builder) error {
		return RecentEvents(rows).Render(context.Background(), w)
	})
	for _, want := range []string{"12:00:00", "shop", "discard"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestRecentEventsEmpty(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return RecentEvents(nil).Render(context.Background(), w)
	})
	if !strings.Contains(out, "No errors recorded") {
		t.Errorf("expected empty-state message, got:\n%s", out)
	}
}

func TestManagePanelRendersControlsAndMessage(t *testing.T) {
	rows := []ManageRow{{Name: "shop", Limit: 3}}
	out := renderString(t, func(w *strings.Builder) error {
		return ManagePanel(rows, "pool added", false).Render(context.Background(), w)
	})
	for _, want := range []string{"shop", "/pools/shop/resize", "/pools/shop/remove", "pool added"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, `class="notice error"`) {
		t.Error("a non-error message must not use the error style")
	}
}

func TestManagePanelErrorStyling(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return ManagePanel(nil, "something broke", true).Render(context.Background(), w)
	})
	if !strings.Contains(out, "something broke") {
		t.Error("expected the error message in output")
	}
	if !strings.Contains(out, "error") {
		t.Error("expected the error CSS class to be applied")
	}
}

func TestReloadResultRendersMultipleLines(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return ReloadResult([]string{"config valid.", "no changes."}, false).Render(context.Background(), w)
	})
	if !strings.Contains(out, "config valid.") || !strings.Contains(out, "no changes.") {
		t.Errorf("expected both lines present, got:\n%s", out)
	}
}

func TestPageRendersFourTabsWithStatusDefaultVisible(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return Page(nil, nil, nil, nil).Render(context.Background(), w)
	})

	for _, want := range []string{
		`data-tab="status"`, `data-tab="sessions"`, `data-tab="manage"`, `data-tab="errors"`,
		"Live status", "Sessions", "Manage pools", "Recent errors",
		`id="tab-status"`, `id="tab-sessions"`, `id="tab-manage"`, `id="tab-errors"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected page to contain %q", want)
		}
	}

	statusIdx := strings.Index(out, `id="tab-status"`)
	sessionsIdx := strings.Index(out, `id="tab-sessions"`)
	if statusIdx < 0 || sessionsIdx < 0 {
		t.Fatal("could not locate tab panels")
	}
	statusTag := out[statusIdx : statusIdx+60]
	sessionsTag := out[sessionsIdx : sessionsIdx+60]
	if strings.Contains(statusTag, "hidden") {
		t.Error("the status tab must be visible by default")
	}
	if !strings.Contains(sessionsTag, "hidden") {
		t.Error("the sessions tab must be hidden by default")
	}
}

func TestPageRendersAllSections(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return Page(
			[]PoolRow{{Name: "shop", Limit: 2}},
			[]SessionRow{{PID: 1, User: "u", Database: "d"}},
			[]EventRow{{Time: "t", Pool: "p", Kind: "k"}},
			[]ManageRow{{Name: "shop", Limit: 2}},
		).Render(context.Background(), w)
	})
	for _, want := range []string{"<!doctype html", "pgman", "shop", "sse-connect=\"/events\"", `id="pools"`, `id="sessions"`, `id="events"`, `id="manage-panel"`} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("expected page to contain %q", want)
		}
	}
}
