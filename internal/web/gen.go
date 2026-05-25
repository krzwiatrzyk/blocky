// Package web — code generation notes.
//
// Generated artefacts are built by `task gen:templ` and `task gen:tailwind`
// (see the Taskfile). They live alongside this file:
//
//   - views/**/*_templ.go (from a-h/templ)
//   - static/tailwind.css (from the standalone tailwindcss CLI)
//
// No //go:generate directive here on purpose: the Taskfile is the single
// source of truth, and templ needs PATH wiring that bare `go generate`
// can't reliably express.
package web
