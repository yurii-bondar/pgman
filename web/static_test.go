package web

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestStaticAssetsAreEmbedded: the page is useless without these two
// files, and an embed directive that quietly matches nothing is a
// build-time success and a runtime 404.
func TestStaticAssetsAreEmbedded(t *testing.T) {
	for _, name := range []string{"static/htmx.min.js", "static/htmx-ext-sse.js"} {
		data, err := fs.ReadFile(Static, name)
		if err != nil {
			t.Errorf("%s is not embedded: %v", name, err)
			continue
		}
		if len(data) < 1024 {
			t.Errorf("%s is %d bytes — too small to be the real library", name, len(data))
		}
		if !strings.Contains(string(data), "htmx") {
			t.Errorf("%s does not look like htmx or its extension", name)
		}
	}
}

// scriptSrc matches the src of every <script> tag with one.
var scriptSrc = regexp.MustCompile(`<script src="([^"]+)"`)

// TestPageLoadsScriptsFromTheBinary is the regression that matters. The
// admin page used to pull htmx from unpkg.com, which meant the dashboard
// needed public internet egress from wherever the proxy runs, and that
// whoever controlled that response controlled a page which can PAUSE
// pools and cancel sessions.
func TestPageLoadsScriptsFromTheBinary(t *testing.T) {
	out := renderString(t, func(w *strings.Builder) error {
		return Page(nil, nil, nil, nil).Render(context.Background(), w)
	})

	matches := scriptSrc.FindAllStringSubmatch(out, -1)
	if len(matches) == 0 {
		t.Fatal("the page loads no scripts at all — htmx is what makes it work")
	}
	for _, m := range matches {
		src := m[1]
		if !strings.HasPrefix(src, "/static/") {
			t.Errorf("script src %q is not served from the binary", src)
		}
		// Every referenced file must actually be embedded, so a rename
		// on one side of the pair fails here rather than in a browser.
		if _, err := fs.ReadFile(Static, strings.TrimPrefix(src, "/")); err != nil {
			t.Errorf("script src %q has no embedded file: %v", src, err)
		}
	}
}
