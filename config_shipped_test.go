package main

import (
	"testing"
	"time"
)

// TestShippedConfigsParse: the YAML files in this repository are the
// reference documentation for every key, which makes a typo in one of
// them a documentation bug that only shows up when somebody copies it.
// They are also the only place a new key's example usage lives, so this
// fails loudly when a key is renamed in Go and not in the samples.
func TestShippedConfigsParse(t *testing.T) {
	for _, path := range []string{"config.yaml", "config.local.yaml", "config.docker.yaml"} {
		t.Run(path, func(t *testing.T) {
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if len(cfg.Pools) == 0 {
				t.Error("no pools parsed out of a file that defines them")
			}
		})
	}
}

// TestShippedConfigTightensTheDefaultCeilings pins the relationship
// between the two: config.yaml exists to show an operator what a
// considered setting looks like, so a sample that is looser than the
// built-in default would be advice to relax.
func TestShippedConfigTightensTheDefaultCeilings(t *testing.T) {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	for _, tc := range []struct {
		key     string
		sample  time.Duration
		builtin time.Duration
	}{
		{"query_timeout", cfg.QueryTimeout, defaultQueryTimeout},
		{"client_idle_timeout", cfg.ClientIdleTimeout, defaultClientIdleTimeout},
		{"idle_transaction_timeout", cfg.IdleTransactionTimeout, defaultIdleTransactionTimeout},
	} {
		if tc.sample <= 0 {
			t.Errorf("%s is disabled in the sample config", tc.key)
			continue
		}
		if tc.sample > tc.builtin {
			t.Errorf("%s: sample %v is looser than the built-in default %v",
				tc.key, tc.sample, tc.builtin)
		}
	}
}
