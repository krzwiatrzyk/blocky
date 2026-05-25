// Package config loads all runtime configuration from environment variables.
package config

import (
	"fmt"

	"blocky/internal/policy"
	"github.com/caarlos0/env/v11"
)

// Config holds blocky daemon and client configuration.
type Config struct {
	APIAddr              string `env:"BLOCKY_API_ADDR" envDefault:"0.0.0.0:8080"`
	LogLevel             string `env:"BLOCKY_LOG_LEVEL" envDefault:"info"`
	LogFormat            string `env:"BLOCKY_LOG_FORMAT" envDefault:"json"`
	DockerHost           string `env:"BLOCKY_DOCKER_HOST" envDefault:"unix:///var/run/docker.sock"`
	MaxRulesPerContainer int    `env:"BLOCKY_MAX_RULES_PER_CONTAINER" envDefault:"16"`
	CTMapSize            int    `env:"BLOCKY_CT_MAP_SIZE" envDefault:"16384"`
	DNSCachePerContainer int    `env:"BLOCKY_DNS_CACHE_PER_CONTAINER" envDefault:"1024"`
	// FlowCacheSize bounds the in-memory ring of recent flow events. The
	// /v1/flows endpoint and dashboard WS replay read from it; at 5000
	// entries memory cost is roughly 1.3 MB.
	FlowCacheSize int `env:"BLOCKY_FLOW_CACHE_SIZE" envDefault:"5000"`
}

// Load parses configuration from the environment and validates basic invariants.
func Load() (Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return Config{}, fmt.Errorf("parse env: %w", err)
	}
	if cfg.MaxRulesPerContainer < 1 || cfg.MaxRulesPerContainer > policy.MaxRulesPerKind {
		return Config{}, fmt.Errorf("BLOCKY_MAX_RULES_PER_CONTAINER=%d outside [1,%d]",
			cfg.MaxRulesPerContainer, policy.MaxRulesPerKind)
	}
	if cfg.LogFormat != "json" && cfg.LogFormat != "console" {
		return Config{}, fmt.Errorf("BLOCKY_LOG_FORMAT=%q must be json|console", cfg.LogFormat)
	}
	if cfg.DNSCachePerContainer < 1 {
		return Config{}, fmt.Errorf("BLOCKY_DNS_CACHE_PER_CONTAINER=%d must be ≥ 1", cfg.DNSCachePerContainer)
	}
	if cfg.FlowCacheSize < 1 {
		return Config{}, fmt.Errorf("BLOCKY_FLOW_CACHE_SIZE=%d must be ≥ 1", cfg.FlowCacheSize)
	}
	return cfg, nil
}
