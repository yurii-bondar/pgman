package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStaticHandlerServesEmbeddedScripts pairs with the template: the
// page asks for /static/htmx.min.js, and this is the route that has to
// answer it. A mismatch between the two is a dashboard that renders and
// then does nothing at all.
func TestStaticHandlerServesEmbeddedScripts(t *testing.T) {
	h := staticHandler()

	for _, path := range []string{"/static/htmx.min.js", "/static/htmx-ext-sse.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
			continue
		}
		if body := rec.Body.String(); !strings.Contains(body, "htmx") {
			t.Errorf("GET %s returned %d bytes that do not look like htmx", path, len(body))
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Errorf("GET %s Content-Type = %q, want a JavaScript type", path, ct)
		}
		// Short and private: the filenames carry no content hash, so a
		// long-lived public cache entry would survive an upgrade.
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "private") {
			t.Errorf("GET %s Cache-Control = %q, want it marked private", path, cc)
		}
	}
}

// TestStaticHandlerDoesNotServeTheRepository: embedding a directory
// embeds everything in it, and the handler is a file server. A request
// for something that is not one of the scripts must not find anything.
func TestStaticHandlerDoesNotEscapeItsDirectory(t *testing.T) {
	h := staticHandler()

	for _, path := range []string{
		"/static/../config.yaml",
		"/static/../../etc/passwd",
		"/config.yaml",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s returned 200 — the file server reached outside static/", path)
		}
	}
}
