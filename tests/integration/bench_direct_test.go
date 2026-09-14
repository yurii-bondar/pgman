//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BenchmarkDirectConcurrent bypasses pgman entirely — talks pgx →
// Postgres directly. Paired with BenchmarkProxyConcurrent this
// measures the pure proxy overhead: (ns/op proxy) − (ns/op direct).
func BenchmarkDirectConcurrent(b *testing.B) {
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(pgDSN + "&default_query_exec_mode=simple_protocol")
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		b.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var dummy int
	_ = pool.QueryRow(ctx, "SELECT 1").Scan(&dummy) // warm

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var n int
		for pb.Next() {
			if err := pool.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil {
				b.Fatalf("query: %v", err)
			}
		}
	})
}
