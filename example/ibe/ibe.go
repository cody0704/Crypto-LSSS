package main

import (
	"crypto/rand"
	"log"
	"math/big"

	pbc "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func main() {
	m := big.NewInt(123456789)
	log.Println("message:", m)

	_, g1, err := pbc.RandomG1(rand.Reader)
	if err != nil {
		log.Fatal("Error:", err)
	}
	log.Println()

	qid := pbc.RandomG1(rand.Reader)

}
