// Command registry starts the ANS registry server.
//
// Environment variables:
//
//	ANS_ADDR   – listen address (default ":8080")
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ReZorg/ans-registry/internal/api"
	"github.com/ReZorg/ans-registry/internal/ra"
	"github.com/ReZorg/ans-registry/internal/store"
	"github.com/ReZorg/ans-registry/internal/tl"
)

func main() {
	s := store.New()

	log_, err := tl.New(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise transparency log: %v\n", err)
		os.Exit(1)
	}

	reg, err := ra.New(s, log_)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise registration authority: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	api.New(mux, reg, log_, s)

	addr := os.Getenv("ANS_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("ANS registry listening on %s (RA=%s)", addr, reg.RAID())
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
