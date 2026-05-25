package policy_test

import (
	"strings"
	"testing"

	"blocky/internal/policy"
	"blocky/internal/types"
)

func TestParseDomains(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		label   string
		maxRule int
		want    types.Policy
		wantErr string
	}{
		{
			name:    "empty label means no rules",
			label:   "",
			maxRule: 16,
			want:    types.Policy{},
		},
		{
			name:    "whitespace only",
			label:   "   ",
			maxRule: 16,
			want:    types.Policy{},
		},
		{
			name:    "single exact",
			label:   "www.google.com",
			maxRule: 16,
			want:    types.Policy{Exact: []string{"www.google.com"}},
		},
		{
			name:    "single suffix",
			label:   "*.googleapis.com",
			maxRule: 16,
			want:    types.Policy{Suffix: []string{"googleapis.com"}},
		},
		{
			name:    "mix and trim",
			label:   " www.google.com , *.googleapis.com , api.github.com ",
			maxRule: 16,
			want: types.Policy{
				Exact:  []string{"www.google.com", "api.github.com"},
				Suffix: []string{"googleapis.com"},
			},
		},
		{
			name:    "lowercases input",
			label:   "WWW.Google.COM,*.GoogleAPIs.com",
			maxRule: 16,
			want: types.Policy{
				Exact:  []string{"www.google.com"},
				Suffix: []string{"googleapis.com"},
			},
		},
		{
			name:    "drops duplicates",
			label:   "a.com,a.com,*.b.com,*.b.com",
			maxRule: 16,
			want: types.Policy{
				Exact:  []string{"a.com"},
				Suffix: []string{"b.com"},
			},
		},
		{
			name:    "rejects invalid hostname",
			label:   "not a host!",
			maxRule: 16,
			wantErr: "invalid hostname",
		},
		{
			name:    "rejects nested wildcard",
			label:   "*.*.example.com",
			maxRule: 16,
			wantErr: "wildcard must be exactly one '*.' prefix",
		},
		{
			name:    "rejects mid wildcard",
			label:   "api.*.example.com",
			maxRule: 16,
			wantErr: "wildcard must be exactly one '*.' prefix",
		},
		{
			name:    "rejects too many exact rules",
			label:   "a.com,b.com,c.com",
			maxRule: 2,
			wantErr: "too many exact rules",
		},
		{
			name:    "rejects too many suffix rules",
			label:   "*.a.com,*.b.com,*.c.com",
			maxRule: 2,
			wantErr: "too many suffix rules",
		},
		{
			name:    "rejects hostname over MaxHostLen bytes",
			label:   strings.Repeat("a", policy.MaxHostLen+1),
			maxRule: 16,
			wantErr: "invalid hostname",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := policy.ParseDomains(tc.label, tc.maxRule)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slicesEqual(got.Exact, tc.want.Exact) {
				t.Fatalf("Exact mismatch: got %v want %v", got.Exact, tc.want.Exact)
			}
			if !slicesEqual(got.Suffix, tc.want.Suffix) {
				t.Fatalf("Suffix mismatch: got %v want %v", got.Suffix, tc.want.Suffix)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		label   string
		want    []uint16
		wantErr string
	}{
		{
			name:  "empty means nil",
			label: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			label: "   ",
			want:  nil,
		},
		{
			name:  "single port",
			label: "443",
			want:  []uint16{443},
		},
		{
			name:  "trim and dedup",
			label: " 53 , 443 , 53 ",
			want:  []uint16{53, 443},
		},
		{
			name:  "preserves first-seen order",
			label: "8443,443,53",
			want:  []uint16{8443, 443, 53},
		},
		{
			name:    "rejects zero",
			label:   "0",
			wantErr: "out of range",
		},
		{
			name:    "rejects above 65535",
			label:   "65536",
			wantErr: "out of range",
		},
		{
			name:    "rejects negative",
			label:   "-1",
			wantErr: "out of range",
		},
		{
			name:    "rejects non-numeric",
			label:   "abc",
			wantErr: "invalid syntax",
		},
		{
			name:    "rejects too many",
			label:   "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17",
			wantErr: "too many ports",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := policy.ParsePorts(tc.label)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !portSlicesEqual(got, tc.want) {
				t.Fatalf("ports mismatch: got %v want %v", got, tc.want)
			}
		})
	}
}

func portSlicesEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMatches(t *testing.T) {
	t.Parallel()
	p := types.Policy{
		Exact:  []string{"www.google.com"},
		Suffix: []string{"googleapis.com"},
	}
	cases := []struct {
		host string
		want bool
	}{
		{"www.google.com", true},
		{"WWW.Google.COM", true}, // case-insensitive
		{"oauth2.googleapis.com", true},
		{"sub.oauth2.googleapis.com", true},
		{"googleapis.com", true},     // bare suffix matches itself
		{"notgoogleapis.com", false}, // anchored: must be label boundary
		{"www.bing.com", false},
		{"google.com", false},
		{"", false},
	}
	for _, tc := range cases {
		got := policy.Matches(p, tc.host)
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
