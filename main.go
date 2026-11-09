package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/act-security/terraform-provider-act/internal/provider"
)

var version = "dev"

func main() {
	var (
		debug   bool
		address string
	)

	flag.BoolVar(&debug, "debug", false, "run the provider in debug mode, for attaching a debugger such as delve")
	flag.StringVar(&address, "address", "registry.terraform.io/act-security/act", "provider source address, as in required_providers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: address,
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatalf("terraform-provider-act: %v", err)
	}
}
