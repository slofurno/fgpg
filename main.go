package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// --keyid-format=long --status-fd=1 --verify /tmp/.git_vtag_tmpeub7HI -
// --status-fd=2 -bsau EAED3DD4

func isVerify() bool {
	for _, arg := range os.Args {
		if strings.Index(arg, "verify") >= 0 {
			return true
		}
	}

	return false
}

var keyfile string

func main() {

	if isVerify() {
		verify()
	} else {
		sign()
	}
}

func makeKeyring() *crypto.KeyRing {
	keyfile := os.Getenv("PGP_PRIVATE_KEY")

	b, err := ioutil.ReadFile(keyfile)
	if err != nil {
		panic(err)
	}

	key, err := crypto.NewKeyFromArmored(string(b))
	if err != nil {
		panic(err)
	}

	keyring, err := crypto.NewKeyRing(key)
	if err != nil {
		panic(err)
	}

	return keyring
}

func verify() {
	t := os.Args[4]
	sig, err := ioutil.ReadFile(t)
	if err != nil {
		panic(err)
	}

	pgpSignature, err := crypto.NewPGPSignatureFromArmored(string(sig))
	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	message := crypto.NewPlainMessage(b)

	keyring := makeKeyring()

	err = keyring.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())
	if err != nil {
		panic(err)
	}

	// Signature verified. Signed by slofurno 2 minutes ago (2022-04-25 22:04:13 +0000 UTC).
	//PGP Fingerprint: 250a7a599def57bee405f9236520052ceaed3dd4.

	fmt.Printf("\n[GNUPG:] VALIDSIG  ")
}

func sign() {
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	msg := crypto.NewPlainMessage(data)

	keyring := makeKeyring()
	sig, err := keyring.SignDetached(msg)

	s, err := sig.GetArmored()
	if err != nil {
		panic(err)
	}

	fmt.Println(s)
	fmt.Fprintf(os.Stderr, "\n[GNUPG:] SIG_CREATED ")
}
