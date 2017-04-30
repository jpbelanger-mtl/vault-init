/*

The format is pretty simple, see doc at https://www.vaultproject.io/docs/http/sys-init.html

We send the /v1/sys/init command thru the vault api. We will provide the GPG keys needed to encrypt the
key shares with each of OPS individual public keys.

They will then be distributed to their owner.

*/
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	vaultpgp "github.com/hashicorp/vault/helper/pgpkeys"
	"golang.org/x/crypto/openpgp"
)

func sendEmails(smtpFrom string, smtpHost *string, gpgKey []byte, vaultKey string, clustername *string) {
	entitylist, err := openpgp.ReadKeyRing(bytes.NewBuffer(gpgKey))
	if err != nil {
		panic(err)
	}

	//For each Identities present into that key, send an email to the recipient with his encrypted shared vault key
	for k, v := range entitylist[0].Identities {
		fmt.Printf("\t\tSending key %v to %s\n", k, v.UserId.Email)
		sendEmail(smtpFrom, smtpHost, v.UserId.Email, vaultKey, clustername)
	}
}

func validateSmtp(smtpHost string) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(smtpHost)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	c.Verify("support@appdirect.com")
}

func sendEmail(smtpFrom string, smtpHost *string, recipient string, vaultKey string, clustername *string) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(*smtpHost)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail(smtpFrom)
	c.Rcpt(recipient)
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	body := fmt.Sprintf("Subject: Vault initialization!\r\nA new vault cluster (%s) init was done.\nEnjoy your shiny new shared key. It is encrypted with your gpg key.\n---CUT HERE---\n%s\n---CUT HERE---", *clustername, vaultKey)
	buf := bytes.NewBufferString(body)
	if _, err = buf.WriteTo(wc); err != nil {
		log.Fatal(err)
	}
}

func main() {
	var smtpFrom = flag.String("smtpFrom", "", "From email address")
	var smtpHost = flag.String("smtpHost", "localhost:25", "SMTP host to use in <host>:<port> format")
	var vaultURL = flag.String("vaultURL", "http://127.0.0.1:8200", "Vault cluster url in http(s)://<host>:<port> format")
	var secretShares = flag.Int("secretShares", 5, "Number of secret shared key to generate")
	var secretThreshold = flag.Int("secretThreshold", 3, "Secret threshold for unsealing the vault")
	var keybaseList = flag.String("keybase", "", "Comma-separated list of keybase account to fetch key from")

	flag.Parse()

	if *smtpFrom == "" {
		print("smtpFrom is required, please provide a valid email address")
		os.Exit(1)
	}

	if *keybaseList == "" {
		print("keybase is required, please provide a valid list of keybase account")
		os.Exit(1)
	}

	keybases := strings.Split(*keybaseList, ",")
	if len(keybases) == 0 {
		print("keybase must contains at least one account name")
		os.Exit(1)
	}

	fmt.Printf("Initializing vault client\n")
	vaultconfig := vaultapi.DefaultConfig()
	vaultconfig.Address = *vaultURL
	vault, err := vaultapi.NewClient(vaultconfig)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Initializing smtp client\n")
	validateSmtp(*smtpHost)

	fmt.Printf("Checking vault state\n")
	initialized, err := vault.Sys().InitStatus()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Vault is initialized: %v\n", initialized)

	if !initialized {
		initRequest := vaultapi.InitRequest{
			SecretShares:    *secretShares,
			SecretThreshold: *secretThreshold,
		}

		splitValues := strings.Split(*keybaseList, ",")
		keybaseMap, err := vaultpgp.FetchKeybasePubkeys(splitValues)

		for _, keyfile := range splitValues {
			key := keybaseMap[keyfile]
			if key == "" {
				fmt.Printf("key for keybase user %s was not found in the map", keyfile)
			}

			initRequest.PGPKeys = append(initRequest.PGPKeys, key)
		}

		fmt.Printf("\nVault will be initialized with the following config: \n")
		fmt.Printf("Total secret shares: %v\n", initRequest.SecretShares)
		fmt.Printf("Secret threshold: %v\n", initRequest.SecretThreshold)
		fmt.Printf("Number of GPG keys: %v\n\n", len(initRequest.PGPKeys))

		initResponse, err := vault.Sys().Init(&initRequest)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Cluster was initialized with %v shares\n\n", len(initRequest.PGPKeys))
		fmt.Printf("\troot token: %v\n\t", initResponse.RootToken)
		fmt.Printf("Sending secret shares to each owners by email, processing count: %v\n", len(initResponse.Keys))

		for index, keyB64 := range initResponse.Keys {
			//Decoding the base64 (non-armored) PGP key into binary
			decodedKey, err := base64.StdEncoding.DecodeString(initRequest.PGPKeys[index])
			if err != nil {
				panic(err)
			}
			sendEmails(*smtpFrom, smtpHost, decodedKey, keyB64, vaultURL)
		}
		fmt.Printf("\nProcessing done...\n")
	} else {
		fmt.Printf("Cluster is already initialized, nothing to do")
	}
}