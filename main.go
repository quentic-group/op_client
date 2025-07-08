package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/1password/onepassword-sdk-go"
	"github.com/jessevdk/go-flags"
)

type Secret struct {
	MemorablePassword string `json:"memorablePassword"`
	RandomPaswword    string `json:"randomPassword"`
	SSHKey            string `json:"ssh_key"`
}

type Options struct {
	SecretRef               string `short:"s" long:"secret-ref" description:"secret reference" required:"false"`
	CreateSSH               bool   `long:"create-ssh" description:"create SSH Key" required:"false"`
	CreatePasswordMemorable bool   `long:"create-password-memorable" description:"create password" required:"false"`
	CreatePassword          bool   `long:"create-password" description:"create password" required:"false"`
}

func createSSHKey() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	sshKeyPEMBytes := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}))

	return sshKeyPEMBytes
}

func createPasswordMemorable() string {
	memorablePassword, err := onepassword.Secrets.GeneratePassword(context.Background(), onepassword.NewPasswordRecipeTypeVariantMemorable(&onepassword.PasswordRecipeMemorableInner{
		SeparatorType: onepassword.SeparatorTypeCommas,
		WordListType:  onepassword.WordListTypeFullWords,
		Capitalize:    true,
		WordCount:     10,
	}))
	if err != nil {
		panic(err)
	}
	return memorablePassword.Password
}

func createPassword() string {
	randomPassword, err := onepassword.Secrets.GeneratePassword(context.Background(), onepassword.NewPasswordRecipeTypeVariantRandom(&onepassword.PasswordRecipeRandomInner{
		Length:         40,
		IncludeSymbols: true,
		IncludeDigits:  true,
	}))
	if err != nil {
		panic(err)
	}
	return randomPassword.Password
}

func main() {

	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if opts.SecretRef != "" {
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

	var secret Secret
	if opts.CreateSSH {
		secret.SSHKey = createSSHKey()
	}

	if opts.CreatePasswordMemorable {
		secret.MemorablePassword = createPasswordMemorable()
	}

	if opts.CreatePassword {
		secret.RandomPaswword = createPassword()
	}

	json, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling secret to JSON:", err)
		return
	}

	fmt.Println("Generated secret:", string(json))
}
