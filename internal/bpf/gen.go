// Package bpf compiles and loads the blocky eBPF program.
//
// The go:generate directive below runs bpf2go which:
//   - shells out to clang to compile blocky.c into a CO-RE BPF object
//     once per target architecture
//   - generates Go bindings (blockybpf_x86_bpfel.go, blockybpf_arm64_bpfel.go)
//     embedding the per-arch objects, with build tags so the right one is
//     selected by GOARCH at compile time
//
// `-target amd64,arm64` causes bpf2go to define __TARGET_ARCH_x86 /
// __TARGET_ARCH_arm64 when it invokes clang. The dispatcher in
// headers/vmlinux.h uses those macros to pick between the vendored
// per-arch vmlinux.h snapshots.
//
// Run `task gen` (or `go generate ./...`) after changes to blocky.c.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" blockyBPF blocky.c
