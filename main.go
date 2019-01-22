package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"xincrypto-lsss/lsss"

	"github.com/Nik-U/pbc"
)

type PK struct {
	pairing *pbc.Pairing
	g       []byte
	pubKey  []byte
	p       *big.Int
}

type SK struct {
	attrField []byte
	secret    *big.Int
	vectors   map[string]*big.Int
}

type CT struct {
	ciphertext *big.Int
	signature  []byte
	c1         *big.Int
	c2         *big.Int
}

type DeSigCrypterKey struct {
	userField   map[string][]int
	userVectors map[string]*big.Int
}

func main() {
	// TODO 給系統存取結構 待補...
	sk, pk := systemInit()
	ct := sk.encrypto(pk, "HelloLSSS")

	//解切密者初始化
	dsck := sk.deSingerInit()
	message := dsck.deSignCrypto(pk, ct)

	fmt.Println("message:", message)
}

func systemInit() (sk SK, pk PK) {
	// 限定八節點
	// 簽密者初始化階段
	prefix := lsss.InfixToPrefix("((A+B)*(C+D))*((E+F)*(G+H))")
	fmt.Println(prefix)
	attrField := lsss.AccessTree(prefix)

	secrets := make(map[int]*big.Int)

	for id, key := range attrField {
		fmt.Println(id, key)
	}

	for _, key := range attrField {
		i := 0
		for range key {
			secrets[i], _ = rand.Prime(rand.Reader, 256)
			i++
		}
		fmt.Println("secrets", secrets)
		break
	}

	vectors := make(map[string]*big.Int)
	for id, key := range attrField {
		vectors[id] = big.NewInt(0)
		i := 0
		for _, value := range key {
			temp := big.NewInt(int64(value))
			temp.Mul(temp, secrets[i])
			vectors[id] = vectors[id].Add(vectors[id], temp)
			i++
		}
	}

	fmt.Println("vectors:", vectors)

	jsonAttrField, _ := json.Marshal(attrField)

	sk = SK{attrField: jsonAttrField, secret: secrets[0], vectors: vectors}

	prime, _ := rand.Prime(rand.Reader, 256)

	params := pbc.GenerateA(10, 16)
	pairing := params.NewPairing()

	g := pairing.NewG1().Rand()

	// e(g,g)^alpha
	alpha, _ := rand.Int(rand.Reader, prime)

	pubKey := pairing.NewGT().Pair(g, g)
	pubKey.PowBig(pubKey, alpha)

	pk = PK{pairing: pairing, g: g.Bytes(), pubKey: pubKey.Bytes(), p: prime}

	return
}

func (sk SK) encrypto(pk PK, message string) (ct CT) {

	g := pk.pairing.NewG1().SetBytes(pk.g)

	pubKey := pk.pairing.NewGT().SetBytes(pk.pubKey)
	// pk^s
	privKey := pk.pairing.NewGT().PowBig(pubKey, sk.secret)

	fmt.Println("")
	fmt.Println("")
	fmt.Println("")

	// m to data
	data := m2n(message)

	raw := big.NewInt(12345)

	// hash
	h := pk.pairing.NewG1().SetFromStringHash(message, sha256.New())
	hg := pk.pairing.NewGT().Pair(h, g)
	// signature
	sig := pk.pairing.NewGT().Mul(hg, privKey).Bytes()

	// ABSE encrypt
	c := data.Mul(data, privKey.X())

	// Rand r
	r, _ := rand.Int(rand.Reader, pk.p)

	// Select rand x is private key
	x := new(big.Int).Add(privKey.X(), big.NewInt(0))
	// Select rand x is public key
	y := new(big.Int).Exp(g.X(), x, pk.p)

	// Encrypt
	c1 := new(big.Int).Exp(g.X(), r, pk.p)
	s := new(big.Int).Exp(y, r, pk.p)
	c2 := s.Mul(s, raw)
	c2.Mod(c2, pk.p)

	ct = CT{ciphertext: c, signature: sig, c1: c1, c2: c2}

	return
}

func (sk SK) deSingerInit() (dsck DeSigCrypterKey) {
	// 系統派發使用者金鑰
	// userField := make(map[string][]int)
	// userVectors := make(map[string]*big.Int)

	// UserA Have A B C D
	userField, userVectors := genUserKey("A,B,C,D,E,F,G,H", sk.attrField, sk.vectors)

	dsck = DeSigCrypterKey{userField: userField, userVectors: userVectors}

	return
}

func (dsck DeSigCrypterKey) deSignCrypto(pk PK, ct CT) (message string) {
	// pbc init
	pairing := pk.pairing
	g := pairing.NewG1().SetBytes(pk.g)

	lambda := lsss.SolutionEquation(dsck.userField)

	// DeSecret
	secret := big.NewInt(0)
	i := 0
	for id := range dsck.userField {
		temp := big.NewInt(0)
		temp.Mul(dsck.userVectors[id], big.NewInt(int64(lambda[i])))
		secret.Add(secret, temp)
		i++
	}
	fmt.Println("secret:", secret)

	ciphertext := big.NewInt(0)
	ciphertext.Add(ciphertext, ct.ciphertext)

	// g^s
	// gs := pairing.NewG1().PowBig(g, secret)

	pubKey := pairing.NewGT().SetBytes(pk.pubKey)
	privKey := pairing.NewGT().PowBig(pubKey, secret)

	data := ciphertext.Div(ciphertext, privKey.X())

	// m to data
	message = n2m(data)

	// Verify

	signature := pairing.NewGT().SetBytes(ct.signature)

	h := pairing.NewG1().SetFromStringHash(message, sha256.New())
	hg := pairing.NewGT().Pair(h, g)

	hgg := pairing.NewGT().Mul(hg, pubKey)
	// temp1 := pairing.NewGT().Pair(h, gs)
	// temp2 := pairing.NewGT().Pair(signature, g)

	temp1 := pairing.NewGT().Mul(hgg, privKey)

	temp2 := pairing.NewGT().Mul(signature, pubKey)

	if temp1.Equals(temp2) {
		fmt.Println("Signature verified correctly")
	} else {
		fmt.Println("Signature verified failed")
	}

	x := new(big.Int).Add(privKey.X(), big.NewInt(0))
	fmt.Println("x:", x)
	m := new(big.Int).Exp(ct.c1, x, pk.p)
	m.ModInverse(m, pk.p)
	m.Mul(m, ct.c2)
	m.Mod(m, pk.p)
	fmt.Println("data:", m)

	return
}

func genUserKey(userAttr string, attrField []byte, vectors map[string]*big.Int) (userField map[string][]int, userVectors map[string]*big.Int) {
	var attrField2 map[string][]int
	json.Unmarshal(attrField, &attrField2)

	userAttrs := strings.Split(userAttr, ",")

	userField = make(map[string][]int)
	userVectors = make(map[string]*big.Int)

	var sw bool
	for i := 0; i < len(userAttrs); i++ {
		sw = true
		for j := i + 1; j < len(userAttrs); j++ {
			if intSliceEqualBCE(attrField2[userAttrs[i]], attrField2[userAttrs[j]]) {
				sw = false
				break
			}
		}
		if sw {
			userField[userAttrs[i]] = append(userField[userAttrs[i]], attrField2[userAttrs[i]]...)
			userVectors[userAttrs[i]] = vectors[userAttrs[i]]
		}
	}

	return
}

func intSliceEqualBCE(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	if (a == nil) != (b == nil) {
		return false
	}

	b = b[:len(a)]
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func m2n(m string) *big.Int {
	src := []byte(m)

	encodedStr := hex.EncodeToString(src)

	n := new(big.Int)
	n, _ = n.SetString(encodedStr, 16)

	return n
}

func n2m(m *big.Int) string {
	c := fmt.Sprintf("%x", m)

	dencodedStr, _ := hex.DecodeString(c)

	return string(dencodedStr)
}
