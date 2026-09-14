package main

import "encoding/binary"

// secretBytes builds a big-endian 4-byte SecretKey for tests. Post-v5
// migration SecretKey is []byte across the code, but existing tests
// wrote small uint32 literals like 6 or 42 — this helper preserves the
// same intent without spelling `[]byte{0,0,0,X}` on every line.
func secretBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
