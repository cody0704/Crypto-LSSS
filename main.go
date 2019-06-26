package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"xincrypto-lsss/lib/file"
	"xincrypto-lsss/lsss"

	"github.com/Nik-U/pbc"
)

type PK struct {
	pairing *pbc.Pairing
	g       []byte
	pubKey  []byte
	b       *pbc.Element
}

type SK struct {
	attrField []byte
	secret    *big.Int
	vectors   map[string]*big.Int
	q         map[string]*pbc.Element
	c         map[string]*pbc.Element
	d         map[string]*pbc.Element
	ga        *pbc.Element
}

type CT struct {
	attrField  map[string][]int
	ciphertext *big.Int
	signature  []byte
	q          map[string]*pbc.Element
	c          map[string]*pbc.Element
	d          map[string]*pbc.Element
	cs         *pbc.Element
}

type DeSigCrypterKey struct {
	userField   map[string][]int
	userVectors map[string]*big.Int
}

func main() {
	// TODO 給系統存取結構 待補...
	sk, pk := systemInit()

	fmt.Println("")

	fmt.Println("[Crytpo Data]")
	root := file.GetAllFile("./Logs", "log")
	for _, temp := range root {
		fmt.Println("DataName:", temp.GetFileName())
		fileData, err := ioutil.ReadFile(*temp.Directory) // just pass the file name
		if err != nil {
		}
		fmt.Println(string(fileData))
		fmt.Println()
		//<html><body>dustvalue:0.029296875ug/m3<br />temperature:27.7<br />humidity:49.9%<br />co2:418</body></html>
		ct := sk.encrypto(pk, "ADC")

		fmt.Println(ct)

		//解切密者初始化
		dsck := sk.deSingerInit()
		m := dsck.deSignCrypto(sk.ga, pk, ct)

		fmt.Println("Data:", m)
	}
}

func systemInit() (sk SK, pk PK) {
	zero := big.NewInt(0)

	// 限定八節點
	// 簽密者初始化階段
	prefix := lsss.InfixToPrefix("((A+B)*(C+D))*(E)")
	fmt.Println("Access Policy:", prefix)
	attrField := lsss.AccessTree(prefix)
	fmt.Println()

	secrets := make(map[int]*big.Int)

	for id, key := range attrField {
		fmt.Println(id, key)
	}

	for _, key := range attrField {
		i := 0
		for range key {
			secrets[i], _ = rand.Prime(rand.Reader, 64)
			fmt.Println("secrets", i, secrets[i])
			i++
		}
		break
	}

	fmt.Println()

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

	temps := new(big.Int).Add(vectors["A"], vectors["C"])
	temps.Add(temps, vectors["E"])
	fmt.Println("lambda ", vectors)
	fmt.Println("s ", temps)

	jsonAttrField, _ := json.Marshal(attrField)

	prime, _ := rand.Prime(rand.Reader, 128)

	params := pbc.GenerateA(20, 10)
	pairing := params.NewPairing()

	g := pairing.NewG1().Rand()

	fmt.Println("g:", g)

	// e(g,g)^alpha
	alpha, _ := rand.Int(rand.Reader, prime)
	pubKey := pairing.NewGT().Pair(g, g)
	pubKey.PowBig(pubKey, alpha)

	// g^alpha
	ga := pairing.NewG1().PowBig(g, alpha)

	// B
	bbig, _ := rand.Prime(rand.Reader, 32)
	b := pairing.NewG1().Set0()
	b.Add(b, g)
	b.MulBig(b, bbig)

	q := make(map[string]*pbc.Element)
	qr := make(map[string]*pbc.Element)
	nqr := make(map[string]*pbc.Element)
	d := make(map[string]*pbc.Element)
	r := make(map[string]*big.Int)
	c := make(map[string]*pbc.Element)
	for id, _ := range attrField {
		temp, _ := rand.Prime(rand.Reader, 64)
		q[id] = pairing.NewG1().Set0()
		q[id].Add(q[id], g)
		q[id].PowBig(q[id], temp)

		r[id], _ = rand.Prime(rand.Reader, 36)
		qr[id] = pairing.NewG1().PowBig(q[id], r[id])
		nqr[id] = pairing.NewG1().Invert(qr[id])

		d[id] = pairing.NewG1().Set0()
		d[id].Add(d[id], g)
		d[id].PowBig(d[id], r[id])

		c[id] = pairing.NewG1().Set0()
		c[id].Add(c[id], b)
		c[id].MulBig(c[id], vectors[id])
		if zero.Cmp(vectors[id]) == 1 {
			c[id].Invert(c[id])
		}
		c[id].Mul(c[id], nqr[id])
	}

	privKey := pairing.NewGT().PowBig(pubKey, secrets[0])
	fmt.Println("privKey", privKey.X())

	sk = SK{attrField: jsonAttrField, secret: secrets[0], vectors: vectors, q: q, c: c, d: d, ga: ga}
	pk = PK{pairing: pairing, g: g.Bytes(), pubKey: pubKey.Bytes(), b: b}

	return
}

func (sk SK) encrypto(pk PK, message string) (ct CT) {
	g := pk.pairing.NewG1().SetBytes(pk.g)

	pubKey := pk.pairing.NewGT().SetBytes(pk.pubKey)
	// pk^s
	privKey := pk.pairing.NewGT().PowBig(pubKey, sk.secret)
	// m to data
	data := m2n(message)

	// hash
	h := pk.pairing.NewG1().SetFromStringHash(message, sha256.New())

	hg := pk.pairing.NewGT().Pair(h, g)
	// signature
	sig := pk.pairing.NewGT().Mul(hg, privKey).Bytes()

	fmt.Println("C=", data, "*", privKey.X())
	// ABSE encrypt
	c := data.Mul(data, privKey.X())

	cs := pk.pairing.NewG1().Set0()
	cs.Add(cs, g)
	cs.PowBig(cs, sk.secret)

	var attrField2 map[string][]int
	json.Unmarshal(sk.attrField, &attrField2)

	ct = CT{ciphertext: c, signature: sig, q: sk.q, c: sk.c, d: sk.d, cs: cs, attrField: attrField2}

	return
}

func (sk SK) deSingerInit() (dsck DeSigCrypterKey) {
	// 系統派發使用者金鑰
	// userField := make(map[string][]int)
	// userVectors := make(map[string]*big.Int)

	// UserA Have A B C D
	userField, userVectors := genUserKey("A,C,E", sk.attrField, sk.vectors)

	dsck = DeSigCrypterKey{userField: userField, userVectors: userVectors}

	return
}

func (dsck DeSigCrypterKey) deSignCrypto(ga *pbc.Element, pk PK, ct CT) (message string) {
	// pbc init
	pairing := pk.pairing
	g := pairing.NewG1().SetBytes(pk.g)

	fmt.Println("userField", dsck.userField)
	lambda := lsss.SolutionEquation(dsck.userField)

	// User Key
	tid, _ := rand.Prime(rand.Reader, 36)
	bt := pairing.NewG1().MulBig(pk.b, tid)
	l := pairing.NewG1().MulBig(g, tid)
	kk := pairing.NewG1().Mul(ga, bt)
	fmt.Println("qA", ct.q["A"])

	k := make(map[string]*pbc.Element)
	k["A"] = pairing.NewG1().MulBig(ct.q["A"], tid)
	k["C"] = pairing.NewG1().MulBig(ct.q["C"], tid)
	k["E"] = pairing.NewG1().MulBig(ct.q["E"], tid)
	// End User Key

	// DeKey
	yup := pairing.NewGT().Pair(ct.cs, kk)

	ydown := pairing.NewGT().Set1()

	for id, _ := range ct.attrField {
		if strings.Contains("A,C,E", id) {
			ydown1 := pairing.NewGT().Pair(ct.c[id], l)
			ydown2 := pairing.NewGT().Pair(ct.d[id], k[id])
			ydown3 := pairing.NewGT().Mul(ydown1, ydown2)

			ydown.Mul(ydown, ydown3)
		}
	}
	y := pairing.NewGT().Div(yup, ydown)

	fmt.Println("y", y.X())
	//End DeKey

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
		fmt.Println("")
	} else {
		fmt.Println("")
	}

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
