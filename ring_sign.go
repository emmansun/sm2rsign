package sm2rsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

var (
	one = new(big.Int).SetInt64(1)
)

type ParticipantRandInt func(rand io.Reader, pub *ecdsa.PublicKey, msg []byte) (*big.Int, error)

func SimpleParticipantRandInt(rand io.Reader, pub *ecdsa.PublicKey, msg []byte) (*big.Int, error) {
	return randFieldElement(pub.Curve, rand)
}

// https://www.wangan.com/p/7fyg8kdf13655a55
// 完全采用了sm2签名随机数r的生成方式，只是这里我们使用的默认uid
func SM2ParticipantRandInt(rand io.Reader, pub *ecdsa.PublicKey, msg []byte) (*big.Int, error) {
	m, err := calculateSM2Hash(pub, msg, nil)
	if err != nil {
		return nil, err
	}
	e := hashToInt(m, pub.Curve)

	for {
		k, err := randFieldElement(pub.Curve, rand)
		if err != nil {
			return nil, err
		}

		r, _ := pub.Curve.ScalarBaseMult(k.Bytes()) // (x, y) = k*G
		r.Add(r, e)                                 // r = x + e
		r.Mod(r, pub.Curve.Params().N)              // r = (x + e) mod N
		if r.Sign() != 0 {
			s := new(big.Int).Add(r, k)
			if s.Cmp(pub.Curve.Params().N) != 0 { // if r != 0 && (r + k) != N then ok
				return s, nil
			}
		}
	}
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

func calculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := sm2.CalculateZA(pub, uid)
	if err != nil {
		return nil, err
	}
	md := sm3.New()
	md.Write(za)
	md.Write(data)
	return md.Sum(nil), nil
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	// See randomPoint for notes on the algorithm. This has to match, or s390x
	// signatures will come out different from other architectures, which will
	// break TLS recorded tests.
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

// 这个hash算法没有给出明确定义
func hash(pubs []*ecdsa.PublicKey, msg []byte, cx, cy *big.Int) *big.Int {
	var buffer [32]byte
	h := sm3.New()
	for _, pub := range pubs {
		pub.X.FillBytes(buffer[:])
		h.Write(buffer[:])
		pub.Y.FillBytes(buffer[:])
		h.Write(buffer[:])
	}
	h.Write(msg)
	cx.FillBytes(buffer[:])
	h.Write(buffer[:])
	cy.FillBytes(buffer[:])
	h.Write(buffer[:])
	return hashToInt(h.Sum(nil), pubs[0].Curve)
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// A invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

func getPai(priv *sm2.PrivateKey, pubs []*ecdsa.PublicKey) (int, error) {
	n := len(pubs)
	if n < 2 {
		return -1, errors.New("require multiple SM2 public keys")
	}
	var pai int = -1
	for i := 0; i < len(pubs); i++ {
		if pubs[i].Curve != priv.Curve {
			return -1, errors.New("contains non SM2 public key")
		}
		if priv.PublicKey.Equal(pubs[i]) {
			pai = i
			break
		}
	}
	if pai < 0 {
		return -1, errors.New("does not contain public key of the private key")
	}
	return pai, nil
}

// http://www.jcr.cacrnet.org.cn/CN/10.13868/j.cnki.jcr.000472
func Sign(rand io.Reader, participantRandInt ParticipantRandInt, priv *sm2.PrivateKey, pubs []*ecdsa.PublicKey, msg []byte) ([]*big.Int, error) {
	n := len(pubs)
	pai, err := getPai(priv, pubs)
	if err != nil {
		return nil, err
	}
	// Step 1
	kPai, err := randFieldElement(priv, rand)
	if err != nil {
		return nil, err
	}
	kPaiGx, kPaiGy := priv.ScalarBaseMult(kPai.Bytes())
	c := hash(pubs, msg, kPaiGx, kPaiGy)

	results := make([]*big.Int, n+1)
	// Step 2
	// [pai+1, ... n)
	for i := pai + 1; i < n; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+1] = s
		sx, sy := priv.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, priv.Params().N)
		cx, cy := priv.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		cx, cy = priv.Add(sx, sy, cx, cy)
		c = hash(pubs, msg, cx, cy)
	}
	results[0] = new(big.Int).Set(c)
	// [0...pai)
	for i := 0; i < pai; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+1] = s
		sx, sy := priv.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, priv.Params().N)
		cx, cy := priv.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		cx, cy = priv.Add(sx, sy, cx, cy)
		c = hash(pubs, msg, cx, cy)
	}

	// Step 3: this step is same with SM2 signature scheme
	c.Mul(c, priv.D)
	kPai.Sub(kPai, c)
	dp1 := new(big.Int).Add(priv.D, one)

	var dp1Inv *big.Int

	if in, ok := priv.Curve.(invertible); ok {
		dp1Inv = in.Inverse(dp1)
	} else {
		dp1Inv = fermatInverse(dp1, priv.Params().N) // N != 0
	}

	kPai.Mul(kPai, dp1Inv)
	kPai.Mod(kPai, priv.Params().N) // N != 0

	results[pai+1] = kPai

	return results, nil
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func Verify(pubs []*ecdsa.PublicKey, msg []byte, signature []*big.Int) bool {
	if len(pubs)+1 != len(signature) {
		return false
	}

	c := new(big.Int).Set(signature[0])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+1]
		sx, sy := pub.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, pub.Params().N)
		cx, cy := pub.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		cx, cy = pub.Add(sx, sy, cx, cy)
		c = hash(pubs, msg, cx, cy)
	}

	return c.Cmp(signature[0]) == 0
}
