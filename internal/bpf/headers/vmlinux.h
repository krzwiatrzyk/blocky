/* Dispatcher that picks the per-architecture vmlinux.h based on the
 * __TARGET_ARCH_* macro that bpf2go sets when invoked with
 * `-target amd64,arm64`.
 *
 * The per-arch files are snapshots from github.com/libbpf/vmlinux.h
 * (commit 5c36ac2080a8d3c1216470ce97e6502ed50272e5, kernel v6.19). They
 * are checked into the repo so the build does not depend on the host
 * kernel's BTF. CO-RE resolves struct offsets at load time, so a single
 * snapshot loads cleanly on older/newer kernels.
 *
 * Refresh by re-downloading vmlinux_6.19.h (or the latest tag) from
 * libbpf/vmlinux.h under include/x86/ and include/aarch64/.
 */

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_amd64.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_arm64.h"
#else
#error "vmlinux.h: unknown target arch — invoke bpf2go with -target amd64,arm64"
#endif
