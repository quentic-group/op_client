package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/1password/onepassword-sdk-go"
	"github.com/jessevdk/go-flags"
	"golang.org/x/crypto/ssh"
)

type SSHKey struct {
	PublicKey         string `json:"publicKey"`
	PrivateKeyPKCS8   string `json:"privateKeyPKCS8"`
	PrivateKeyOpenSSH string `json:"privateKeyOpenSSH"`
	Fingerprint       string `json:"fingerprint"`
}
type Secret struct {
	MemorablePassword string `json:"memorablePassword"`
	RandomPaswword    string `json:"randomPassword"`
	SSHKey            SSHKey `json:"ssh_key"`
}

type Options struct {
	SecretRef               string `short:"s" long:"secret-ref" description:"secret reference" required:"false"`
	CreateSSH               bool   `long:"create-ssh" description:"create SSH Key" required:"false"`
	CreatePasswordMemorable bool   `long:"create-password-memorable" description:"create password" required:"false"`
	CreatePassword          bool   `long:"create-password" description:"create password" required:"false"`
}

func createSSHKey() SSHKey {
	// Generate a new ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Failed to generate ED25519 key pair:", err)
	}

	// Convert private key to PKCS#8 PEM format
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatal("Failed to marshal private key:", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Convert public key to SSH format using the ssh package
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		log.Fatal("Failed to create SSH public key:", err)
	}

	// Convert PKCS#8 to OpenSSH format
	opensshKey, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		log.Fatal("Failed to marshal private key to OpenSSH format:", err)
	}

	// Generate fingerprint (SHA256 hash of public key)
	fingerprint := ssh.FingerprintSHA256(sshPublicKey)

	return SSHKey{
		PublicKey:         string(ssh.MarshalAuthorizedKey(sshPublicKey)),
		PrivateKeyPKCS8:   string(privKeyPEM),
		PrivateKeyOpenSSH: string(pem.EncodeToMemory(opensshKey)),
		Fingerprint:       fingerprint,
	}
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

	fmt.Printf("Generated secret: %+v\n", secret)
}
