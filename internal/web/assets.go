package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var staticFS embed.FS

// StaticFileSystem returns an http.FileSystem rooted at the embedded `static/`
// directory. It serves the Tailwind output and the dashboard JS.
func StaticFileSystem() http.FileSystem {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Only happens if the embed directive is wrong; build won't link.
		panic(err)
	}
	return http.FS(sub)
}
