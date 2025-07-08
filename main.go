package main

import (
	"context"
	"fmt"
	"os"

	"github.com/1password/onepassword-sdk-go"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	SecretRef string `short:"s" long:"secret-ref" description:"secret reference" required:"true"`
}

func main() {

	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("My 1Password Integration", "v1.0.0"),
	)
	if err != nil {
		fmt.Println("Error creating 1Password client:", err)
		return
	}

	secret, err := client.Secrets().Resolve(context.TODO(), opts.SecretRef)
	if err != nil {
		fmt.Println("Error resolving secret:", err)
	}
	fmt.Println("Resolved secret:", secret)
}
