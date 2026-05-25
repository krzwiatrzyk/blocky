# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# blocky multi-stage Dockerfile
#
# Stage 1 (builder): runs `task gen` + `go build`. Needs clang/LLVM for the
# eBPF program, the templ CLI for HTML, and the standalone tailwindcss CLI for
# the dashboard stylesheet. Everything ends up baked into one static Go binary
# via go:embed + bpf2go.
#
# Stage 2 (runtime): debian-slim with ca-certificates + curl (for the
# healthcheck). The binary is statically linked (CGO_ENABLED=0), so it doesn't
# care about glibc versions on the host.
#
# Prerequisite on the build host:
#
#   task vmlinux       # generates internal/bpf/headers/vmlinux.h from the
#                      # build host's /sys/kernel/btf/vmlinux
#
# vmlinux.h is gitignored and CANNOT be regenerated from inside the build
# container (Docker build doesn't expose /sys/kernel/btf). The Dockerfile
# below fails fast with a clear error if it's missing.
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Bookworm ships clang-14, which can't compile the inlined-byte-copy patterns
# in internal/bpf/blocky.c — it lowers them through __builtin_memcpy, which
# the BPF backend then rejects. We pull clang-18 from llvm.org's apt repo so
# the container matches what `task gen:bpf` uses on a developer machine.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release \
 && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
 && CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")" \
 && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-18 main" \
        > /etc/apt/sources.list.d/llvm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        clang-18 lld-18 llvm-18 \
        libbpf-dev bpftool make \
 && ln -sf /usr/bin/clang-18 /usr/local/bin/clang \
 && ln -sf /usr/bin/llc-18 /usr/local/bin/llc \
 && ln -sf /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Pre-fetch modules so this layer caches independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

# templ CLI (HTML generator) — version pinned to match go.mod.
RUN go install github.com/a-h/templ/cmd/templ@v0.3.1020

# Standalone tailwindcss CLI (no node/npm required). Picks the right binary
# for the build architecture so the image works on both amd64 and arm64.
RUN ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in \
        amd64) TARCH=x64 ;; \
        arm64) TARCH=arm64 ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -sSfL -o /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-${TARCH}" \
 && chmod +x /usr/local/bin/tailwindcss

# Source tree.
COPY . .

# vmlinux.h is the one piece of build state that has to come from the host
# kernel. Fail fast with a helpful message if the operator forgot to run
# `task vmlinux` before `docker build`.
RUN test -f internal/bpf/headers/vmlinux.h \
 || { echo "ERROR: internal/bpf/headers/vmlinux.h is missing." >&2; \
      echo "Run \"task vmlinux\" on the build host first." >&2; \
      exit 1; }

# Generate everything: templ → _templ.go, tailwind → tailwind.css, bpf2go →
# embedded BPF bytes. The Taskfile knows these orderings; we replay them here
# without depending on Task being installed in the image.
RUN templ generate ./internal/web/...
RUN tailwindcss \
        -i internal/web/static/tailwind.src.css \
        -o internal/web/static/tailwind.css \
        --minify
RUN go generate ./...

# Static build — Go binary needs no glibc / libbpf at runtime.
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/blocky ./cmd/blocky


# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/blocky /usr/local/bin/blocky

EXPOSE 8080

# The Go binary is the entrypoint; `run` is the default subcommand (the
# daemon). Override with `tap` / `version` etc. via `docker run … blocky tap`.
ENTRYPOINT ["/usr/local/bin/blocky"]
CMD ["run"]
