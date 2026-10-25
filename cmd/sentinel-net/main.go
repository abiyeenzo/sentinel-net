package main

import (
	"context"
	"os"

	"github.com/abiyeenzo/sentinel-net/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.DefaultIO()))
}
