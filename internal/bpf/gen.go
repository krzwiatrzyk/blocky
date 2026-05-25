// Package bpf compiles and loads the blocky eBPF program.
//
// The go:generate directive below runs bpf2go which:
//   - shells out to clang to compile blocky.c into a CO-RE BPF object
//   - generates Go bindings (blocky_bpf_bpfel.go) embedding the object
//
// Run `task gen` (or `go generate ./...`) after changes to blocky.c.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu" blockyBPF blocky.c
