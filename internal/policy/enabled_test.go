package policy_test

import (
	"testing"

	"blocky/internal/policy"
	"blocky/internal/types"
)

func TestIsEnabled(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"true":  true,
		"TRUE":  true,
		"True":  true,
		" true ": true,
		"1":     true,
		"yes":   true,
		"on":    true,
		"":      false,
		"false": false,
		"0":     false,
		"no":    false,
		"off":   false,
		// Anything not in the positive list is treated as opted-out so the
		// label can't surface unexpected enablement through typos.
		"sure":     false,
		"enabled":  false,
		"disabled": false,
	}
	for in, want := range cases {
		if got := policy.IsEnabled(in); got != want {
			t.Errorf("IsEnabled(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPolicyIsActive(t *testing.T) {
	t.Parallel()
	if (types.Policy{}).IsActive() {
		t.Error("empty policy must not be active")
	}
	if !(types.Policy{Observe: true}).IsActive() {
		t.Error("observe-only policy must be active")
	}
	if !(types.Policy{Exact: []string{"a.example.com"}}).IsActive() {
		t.Error("exact-rule policy must be active")
	}
	if !(types.Policy{Ports: []uint16{443}}).IsActive() {
		t.Error("port-rule policy must be active")
	}
}
