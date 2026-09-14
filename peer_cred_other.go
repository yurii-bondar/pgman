//go:build !linux

package main

import (
	"fmt"
	"net"
)

// getPeerCred is a stub on non-Linux platforms. macOS uses
// LOCAL_PEERCRED and getpeereid, BSD variants differ again — worth
// implementing per-OS but out of scope for the initial cut.
func getPeerCred(conn net.Conn) (uid, gid uint32, pid int32, err error) {
	_ = conn
	return 0, 0, 0, fmt.Errorf("SO_PEERCRED is not supported on this platform")
}

// peerCredSupported is false — HBAAuth will fail METHOD=peer rules
// at startup here with a clear error, not silently degrade to trust.
const peerCredSupported = false
