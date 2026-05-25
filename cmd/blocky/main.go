// Command blocky is the per-container egress firewall daemon and CLI.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"blocky/internal/config"
	"blocky/internal/daemon"
	"blocky/internal/logging"
	"blocky/internal/tapclient"
	"github.com/spf13/cobra"
)

// Build-time variables; set with -ldflags="-X main.version=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "blocky",
		Short:         "Per-container egress firewall using eBPF",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newRunCmd(), newTapCmd(), newVersionCmd())
	return root
}

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the blocky daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			log := logging.New(cfg)
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return daemon.Run(ctx, cfg, log)
		},
	}
}

func newTapCmd() *cobra.Command {
	var (
		addr      string
		container string
		verdict   string
		format    string
	)
	cmd := &cobra.Command{
		Use:   "tap",
		Short: "Stream live flow events from a running blocky daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if addr == "" {
				addr = cfg.APIAddr
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return tapclient.Run(ctx, tapclient.Options{
				Addr:      addr,
				Container: container,
				Verdict:   verdict,
				Format:    format,
				Stdout:    cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "daemon address host:port (defaults to $BLOCKY_API_ADDR)")
	cmd.Flags().StringVar(&container, "container", "", "filter by container ID or name")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by verdict: allow|drop")
	cmd.Flags().StringVar(&format, "format", "pretty", "output format: pretty|json")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "blocky %s (commit %s, built %s)\n", version, commit, date)
		},
	}
}

func init() {
	cobra.EnableCommandSorting = false
}
