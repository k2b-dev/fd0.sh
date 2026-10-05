package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/desktopbridge"
)

func main() {
	service, err := desktopbridge.NewServiceFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// On shutdown, end running deploys and give them a moment to record the
	// result of the target they were running.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-signals
		desktopbridge.StopDeploys(10 * time.Second)
		os.Exit(0)
	}()
	server := desktopbridge.Server{Handler: service}
	err = server.Serve(context.Background(), os.Stdin, os.Stdout)
	desktopbridge.StopDeploys(10 * time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
