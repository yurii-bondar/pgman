package web

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/a-h/templ"
	templruntime "github.com/a-h/templ/runtime"
)

// errWriteFailed stands in for the client hanging up mid-response. That
// is the only realistic source of a write error in this package: the
// admin page is rendered straight into an http.ResponseWriter, and an
// operator closing the tab during an SSE refresh aborts the write at an
// arbitrary byte offset.
var errWriteFailed = errors.New("web: client went away")

// failingWriter fails the failAt-th Write and every Write after it,
// mirroring a torn TCP connection — once the socket is gone it stays
// gone. writes records how far the render actually got.
type failingWriter struct {
	failAt int
	writes int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.failAt > 0 && w.writes >= w.failAt {
		return 0, errWriteFailed
	}
	return len(p), nil
}

// unbufferedRender renders comp with the output buffer sized down to a
// single byte, so every fragment the component emits reaches w as its
// own Write. templ normally wraps the writer in a 4KB buffer, which
// would collapse a whole component into one or two syscalls and hide
// every error path but the last from the test.
//
// The component is handed a *templruntime.Buffer directly, which templ
// adopts as-is: that keeps the buffer out of templ's global pool, so
// shrinking DefaultBufferSize cannot leak into any other test.
func unbufferedRender(comp templ.Component, w *failingWriter) error {
	original := templruntime.DefaultBufferSize
	templruntime.DefaultBufferSize = 1
	defer func() { templruntime.DefaultBufferSize = original }()

	buf := &templruntime.Buffer{}
	buf.Reset(w)
	return comp.Render(context.Background(), buf)
}

// coverageComponents is every component in the package, each with rows
// populated so the per-row loops and the conditional fragments inside
// them are actually entered.
func coverageComponents() []struct {
	name string
	comp templ.Component
} {
	poolRows := []PoolRow{
		{Name: "shop", Limit: 2, InUse: 2, Idle: 1, AcquireTotal: 9, AcquireSeconds: 0.5, Discards: 1, DialErrors: 2},
		{Name: "analytics", Limit: 4, InUse: 1},
	}
	sessionRows := []SessionRow{
		{PID: 1, User: "alice", Database: "db1", Active: true, ConnectedFor: "5s", TxFor: "1s"},
		{PID: 2, User: "bob", Database: "db2", ConnectedFor: "9s"},
	}
	eventRows := []EventRow{{Time: "12:00:00", Pool: "shop", Kind: "dial_error", Err: "refused"}}
	manageRows := []ManageRow{{Name: "shop", Limit: 2}}

	return []struct {
		name string
		comp templ.Component
	}{
		{"pageStyle", pageStyle()},
		{"PoolsTable", PoolsTable(poolRows)},
		{"PoolsTable/empty", PoolsTable(nil)},
		{"SessionsTable", SessionsTable(sessionRows)},
		{"SessionsTable/empty", SessionsTable(nil)},
		{"RecentEvents", RecentEvents(eventRows)},
		{"RecentEvents/empty", RecentEvents(nil)},
		{"ReloadResult", ReloadResult([]string{"config valid.", "no changes."}, true)},
		{"ManagePanel", ManagePanel(manageRows, "pool added", false)},
		{"ManagePanel/empty", ManagePanel(nil, "", false)},
		{"Page", Page(poolRows, sessionRows, eventRows, manageRows)},
	}
}

// TestRenderStopsAtTheFirstWriteError is the contract the /events SSE
// handler depends on: when a browser disconnects mid-render, every
// component must abandon the response and return the error rather than
// pressing on. A component that swallows it keeps formatting rows into
// a dead socket for as long as the page would have taken to render,
// and — worse — reports success, so the handler never learns the client
// is gone and keeps it in the subscriber set.
//
// Every write position is exercised, because the error handling is
// repeated once per emitted fragment and a single missed check would
// only surface for one specific truncation point.
func TestRenderStopsAtTheFirstWriteError(t *testing.T) {
	for _, c := range coverageComponents() {
		// First learn how many writes a clean render performs, so the
		// sweep below covers exactly the reachable positions.
		counter := &failingWriter{}
		if err := unbufferedRender(c.comp, counter); err != nil {
			t.Fatalf("%s: clean render failed: %v", c.name, err)
		}
		if counter.writes == 0 {
			t.Fatalf("%s: rendered nothing", c.name)
		}

		for failAt := 1; failAt <= counter.writes; failAt++ {
			w := &failingWriter{failAt: failAt}
			err := unbufferedRender(c.comp, w)
			if err == nil {
				t.Errorf("%s: render succeeded although write %d of %d failed",
					c.name, failAt, counter.writes)
			}
			if !errors.Is(err, errWriteFailed) {
				t.Errorf("%s: write %d returned %v, want the writer's own error",
					c.name, failAt, err)
			}
		}
	}
}

// TestRenderSurfacesTheDeferredFlushError covers the other half of the
// write-error story. templ buffers small components in full, so a
// component whose output fits in one buffer performs no write at all
// until the deferred flush — and it is the flush, not any individual
// fragment, that discovers the connection is gone. Dropping that error
// would make every short fragment (the SSE payloads, which are short by
// design) report success no matter what happened on the wire.
func TestRenderSurfacesTheDeferredFlushError(t *testing.T) {
	// PoolsTable's empty state is a few hundred bytes — comfortably
	// inside templ's default buffer, so nothing is written before the
	// flush. A plain io.Writer (not a templ buffer) is what makes templ
	// own the buffering and therefore the flush.
	w := &failingWriter{failAt: 1}
	err := PoolsTable(nil).Render(context.Background(), w)
	if !errors.Is(err, errWriteFailed) {
		t.Fatalf("render returned %v, want the flush error", err)
	}
	if w.writes != 1 {
		t.Errorf("underlying writer saw %d writes, want 1 (the flush)", w.writes)
	}
}

// TestRenderAbortsOnACancelledContext matters because the admin handler
// renders under the request context. Once the client is gone, the
// context is cancelled, and a component that renders anyway spends CPU
// formatting a snapshot of every pool and session for a response nobody
// will read — on the SSE endpoint, once every refresh interval, for as
// long as the stale subscriber is kept around.
func TestRenderAbortsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, c := range coverageComponents() {
		var buf strings.Builder
		err := c.comp.Render(ctx, &buf)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: render returned %v, want context.Canceled", c.name, err)
		}
		if buf.Len() != 0 {
			t.Errorf("%s: wrote %d bytes for a cancelled request", c.name, buf.Len())
		}
	}
}

// TestPageStyleIsSelfContained renders the style block on its own, the
// way no caller does — Page always inlines it — because that is the only
// place its content can be asserted directly. What matters is that the
// dashboard's whole appearance and its tab switching ship inside the
// binary: the admin page is reachable from networks with no public
// egress, and a stylesheet or script pulled from a CDN would leave it
// unstyled and its tabs dead exactly there.
func TestPageStyleIsSelfContained(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return pageStyle().Render(context.Background(), w)
	})

	for _, want := range []string{"<style>", "</style>", "<script>", "function showTab(", ".tab-panel[hidden]"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the inlined style block to contain %q", want)
		}
	}
	for _, unwanted := range []string{"http://", "https://", "//unpkg", "@import"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the style block reaches outside the binary via %q", unwanted)
		}
	}
}

// TestRenderToleratesANilChildComponent covers the child normalisation
// every generated component starts with. None of these templates take
// children, so they all discard whatever the caller supplied — but they
// still read it first, and a nil value has to become a no-op there
// rather than a nil component the runtime would later try to render.
// The admin handlers compose components through a shared context, so a
// nil child is one refactor away and would otherwise surface as a panic
// inside an HTTP handler.
func TestRenderToleratesANilChildComponent(t *testing.T) {
	for _, c := range coverageComponents() {
		var buf strings.Builder
		ctx := templ.WithChildren(context.Background(), nil)
		if err := c.comp.Render(ctx, &buf); err != nil {
			t.Errorf("%s: render with a nil child: %v", c.name, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("%s: rendered nothing", c.name)
		}
	}
}

// TestRenderEscapesOperatorSuppliedText is why the templates must never
// be replaced by hand-rolled string concatenation. Pool names come from
// the add-pool form and error text comes from the backend, so both are
// attacker-influenced in the sense that matters: the admin page can
// PAUSE pools and cancel sessions, and script injected into it runs with
// the operator's session.
func TestRenderEscapesOperatorSuppliedText(t *testing.T) {
	const payload = `<script>alert(1)</script>`

	cases := []struct {
		name string
		comp templ.Component
	}{
		{"PoolsTable name", PoolsTable([]PoolRow{{Name: payload, Limit: 1}})},
		{"SessionsTable user", SessionsTable([]SessionRow{{PID: 1, User: payload, Database: "db"}})},
		{"RecentEvents error", RecentEvents([]EventRow{{Time: "t", Pool: "p", Kind: "k", Err: payload}})},
		{"ManagePanel message", ManagePanel(nil, payload, true)},
		{"ReloadResult line", ReloadResult([]string{payload}, false)},
	}
	for _, c := range cases {
		var buf strings.Builder
		if err := c.comp.Render(context.Background(), &buf); err != nil {
			t.Fatalf("%s: render: %v", c.name, err)
		}
		if strings.Contains(buf.String(), payload) {
			t.Errorf("%s: rendered the payload unescaped", c.name)
		}
		if !strings.Contains(buf.String(), "&lt;script&gt;") {
			t.Errorf("%s: expected the payload to survive as escaped text", c.name)
		}
	}
}

// TestReloadResultSeparatesOnlyBetweenLines pins the separator logic.
// The reload diff is the one place pgman shows an operator what a config
// change will do before they commit to it, and a stray leading <br>
// pushes the first line — "config valid." or the first error — out of
// the visible notice box.
func TestReloadResultSeparatesOnlyBetweenLines(t *testing.T) {
	single := renderString(t, func(w *strings.Builder) error {
		return ReloadResult([]string{"config valid."}, false).Render(context.Background(), w)
	})
	if strings.Contains(single, "<br>") {
		t.Errorf("a single-line result must not emit a separator, got:\n%s", single)
	}

	triple := renderString(t, func(w *strings.Builder) error {
		return ReloadResult([]string{"a", "b", "c"}, false).Render(context.Background(), w)
	})
	if got := strings.Count(triple, "<br>"); got != 2 {
		t.Errorf("three lines produced %d separators, want 2", got)
	}
}

// TestManagePanelOmitsTheNoticeWhenThereIsNothingToSay guards the
// first-page-load case. The panel is re-rendered wholesale as the
// response to every add/resize/remove, and rendering an empty notice
// div with the error class would leave a red bar sitting above the
// controls on a page where nothing has gone wrong.
func TestManagePanelOmitsTheNoticeWhenThereIsNothingToSay(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return ManagePanel([]ManageRow{{Name: "shop", Limit: 2}}, "", true).Render(context.Background(), w)
	})
	if strings.Contains(out, `<div class="notice`) {
		t.Errorf("an empty message must not render a notice at all, got:\n%s", out)
	}
	if !strings.Contains(out, "/pools/shop/resize") {
		t.Error("the controls must still render without a message")
	}
}
