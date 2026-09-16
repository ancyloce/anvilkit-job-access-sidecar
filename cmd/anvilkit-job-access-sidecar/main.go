// anvilkit-job-access-sidecar is the trusted access sidecar of a Job Pod
// (DD-03 §5): it alone holds the Job's network identity and reaches
// Control; the trusted harness reaches it over trusted.sock, the candidate
// over candidate.sock. It runs as UID 10002 with no capability.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/app"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/config"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration rejected", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("sidecar stopped", "error", err.Error())
		os.Exit(1)
	}
}
