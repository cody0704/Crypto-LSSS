package main

import (
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
)

func main() {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	// g is the generator of G1
	g := pairing.NewG1().Rand()

	//private keys choose
	beta := pairing.NewZr().Rand()

	r := pairing.NewZr().Rand()
	alpha := pairing.NewZr().Rand()
	s := pairing.NewZr().Rand()
	a := pairing.NewZr().Rand()
	//authorizer public keys(G1, g, h = g^beta, f = g^(1/beta))
	beta_invert := pairing.NewZr().Invert(beta)

	h := pairing.NewG1().PowZn(g, beta)
	//owner secret key g^alpha
	OSK := pairing.NewG1().PowZn(g, alpha)
	//owner public key e(g, g)^alpha
	OPK := pairing.NewGT().Pair(g, g)
	OPK.PowZn(OPK, alpha)
	// CT part compute
	C := pairing.NewG1().PowZn(h, s) //C = h^s=g^(beta*s)
	// c_bar compute
	fmt.Println("Before encryption. The raw message is:")
	raw_message := big.NewInt(999999)
	// Do the encryption

	//C_temp = e(g,g)^(alpha*s)
	C_temp := pairing.NewGT().PowZn(OPK, s)
	// C_bar = m*e(g,g)^(alpha*s)
	C_bar := pairing.NewGT().MulBig(C_temp, raw_message)

	//SK co-computed by authorizer and owner
	// compute D
	D := pairing.NewG1().PowZn(g, r)
	D.PowZn(D, a)
	D.Mul(D, OSK)
	D.PowZn(D, beta_invert)

	//decrypt
	// compute A
	A := pairing.NewGT().Pair(g, g)
	A.PowZn(A, r)
	A.PowZn(A, a)
	A.PowZn(A, s)

	//
	cd_pair := pairing.NewGT().Pair(C, D)
	cd_pair.Div(cd_pair, A)
	cd_pair.Div(C_bar, cd_pair)
	//change the message_dec to string

	message_mpz := cd_pair.X()
	fmt.Println("Decrypt successfully. The message is:", message_mpz)

}
