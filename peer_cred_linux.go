//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

// getPeerCred reads SO_PEERCRED off a Unix-domain socket and returns
// the connecting process's UID + GID + PID. Linux-only — the syscall
// number and struct layout differ per kernel, and macOS/BSD use a
// different mechanism (LOCAL_PEERCRED / getpeereid) that we don't
// currently wire up.
func getPeerCred(conn net.Conn) (uid, gid uint32, pid int32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, fmt.Errorf("peer credentials require a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var ucred *syscall.Ucred
	var innerErr error
	err = raw.Control(func(fd uintptr) {
		ucred, innerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, 0, 0, err
	}
	if innerErr != nil {
		return 0, 0, 0, innerErr
	}
	return ucred.Uid, ucred.Gid, ucred.Pid, nil
}

// peerCredSupported returns true because Linux has SO_PEERCRED
// natively. Callers use this to decide whether METHOD=peer in HBA
// can be honored at all.
const peerCredSupported = true
