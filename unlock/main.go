package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func main() {
	b, _ := ioutil.ReadFile(os.Args[1])

	key, err := crypto.NewKeyFromArmored(string(b))
	if err != nil {
		panic(err)
	}

	key, err = key.Unlock([]byte(os.Args[2]))
	if err != nil {
		panic(err)
	}

	unlocked, _ := key.Armor()
	fmt.Println(unlocked)
}
