package main

import (
	"context"
	"os"

	"github.com/abiyeenzo/sentinel-net/internal/cli"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"gui"}
	}
	os.Exit(cli.Run(context.Background(), args, cli.DefaultIO()))
}
