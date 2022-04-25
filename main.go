package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
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
	t := os.Args[2]
	sig, err := ioutil.ReadFile(t)
	if err != nil {
		panic(err)
	}

	signature, err := crypto.NewPGPSignatureFromArmored(string(sig))
	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	message := crypto.NewPlainMessage(b)

	keyring := makeKeyring()

	err = keyring.VerifyDetached(message, signature, crypto.GetUnixTime())
	if err != nil {
		panic(err)
	}

	key, _ := keyring.GetKey(0)
	idents := keyring.GetIdentities()

	fmt.Fprintf(os.Stderr, "Signature verified. Signed by %s.\nPGP Fingerprint: %s\n", idents[0].Email, key.GetFingerprint())
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
}
