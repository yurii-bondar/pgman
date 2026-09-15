package web

import "embed"

// Static holds the admin UI's JavaScript, compiled into the binary.
//
// These files used to be <script src="https://unpkg.com/…"> tags, which
// made the dashboard depend on a third-party CDN being reachable at the
// moment an operator opened it. Two problems with that, and the second
// is the serious one:
//
//   - A proxy in front of a database usually sits somewhere with no
//     egress to the public internet. The page would load and then do
//     nothing: no tables, no SSE stream, no controls.
//   - unpkg served executable code into a page that can PAUSE pools,
//     resize them, remove them and cancel sessions, with no
//     subresource-integrity hash to catch a substitution. Whoever
//     controls that response controls the admin plane.
//
// See static/PROVENANCE.md for the upstream versions and their hashes,
// which is what makes an update reviewable rather than a blob swap.
//
//go:embed static
var Static embed.FS
