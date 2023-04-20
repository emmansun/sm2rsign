package sm2rsign

import (
	"crypto/ecdsa"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

type RingSigner interface {
	Sign(rand io.Reader, participantRandInt ParticipantRandInt, msg []byte) ([]*big.Int, error)
}

type RingVerifier interface {
	Verify(msg []byte, signature []*big.Int) bool
}

type BaseLinkableVerfier struct {
	publicKeys []*ecdsa.PublicKey
}

func NewBaseLinkableVerfier(pubs []*ecdsa.PublicKey) *BaseLinkableVerfier {
	return &BaseLinkableVerfier{publicKeys: pubs}
}

type BaseLinkableSigner struct {
	BaseLinkableVerfier
	privateKey *sm2.PrivateKey
}

func NewBaseLinkableSigner(privateKey *sm2.PrivateKey, pubs []*ecdsa.PublicKey) *BaseLinkableSigner {
	return &BaseLinkableSigner{privateKey: privateKey, BaseLinkableVerfier: BaseLinkableVerfier{publicKeys: pubs}}
}

// 这个Hp 也没有明确算法描述，这里简单使用曲线点加法
func publicKeysToPoint(pubs []*ecdsa.PublicKey) (x *big.Int, y *big.Int) {
	x = pubs[0].X
	y = pubs[0].Y
	for i := 1; i < len(pubs); i++ {
		x, y = pubs[0].Curve.Add(x, y, pubs[i].X, pubs[i].Y)
	}
	return
}

func hash1(pubs []*ecdsa.PublicKey, QpaiX, QpaiY *big.Int, msg []byte, vx, vy, wx, wy *big.Int) *big.Int {
	var buffer [32]byte
	h := sm3.New()
	for _, pub := range pubs {
		pub.X.FillBytes(buffer[:])
		h.Write(buffer[:])
		pub.Y.FillBytes(buffer[:])
		h.Write(buffer[:])
	}

	QpaiX.FillBytes(buffer[:])
	h.Write(buffer[:])
	QpaiY.FillBytes(buffer[:])
	h.Write(buffer[:])

	h.Write(msg)

	if vx != nil && vy != nil {
		vx.FillBytes(buffer[:])
		h.Write(buffer[:])
		vy.FillBytes(buffer[:])
		h.Write(buffer[:])
	}

	if wx != nil && wy != nil {
		wx.FillBytes(buffer[:])
		h.Write(buffer[:])
		wy.FillBytes(buffer[:])
		h.Write(buffer[:])
	}

	return hashToInt(h.Sum(nil), pubs[0].Curve)
}

func (signer *BaseLinkableSigner) Sign(rand io.Reader, participantRandInt ParticipantRandInt, msg []byte) ([]*big.Int, error) {
	priv := signer.privateKey
	pubs := signer.publicKeys

	n := len(pubs)
	pai, err := getPai(priv, pubs)
	if err != nil {
		return nil, err
	}

	// step 1, Qpai
	rx, ry := publicKeysToPoint(pubs)
	QpaiX, QpaiY := priv.ScalarMult(rx, ry, priv.D.Bytes())

	// step 2,
	kPai, err := randFieldElement(priv, rand)
	if err != nil {
		return nil, err
	}
	kPaiGx, kPaiGy := priv.ScalarBaseMult(kPai.Bytes())
	krx, kry := priv.ScalarMult(rx, ry, kPai.Bytes())
	c := hash1(pubs, QpaiX, QpaiY, msg, kPaiGx, kPaiGy, krx, kry)

	results := make([]*big.Int, n+3)
	results[0] = QpaiX
	results[1] = QpaiY
	// Step 3
	// [pai+1, ... n)
	for i := pai + 1; i < n; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		sx, sy := priv.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, priv.Params().N)
		vx, vy := priv.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		vx, vy = priv.Add(sx, sy, vx, vy)

		sx, sy = priv.ScalarMult(rx, ry, s.Bytes())
		wx, wy := priv.ScalarMult(QpaiX, QpaiY, c.Bytes())
		wx, wy = priv.Add(sx, sy, wx, wy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, wx, wy)
	}
	results[2] = new(big.Int).Set(c)
	// [0...pai)
	for i := 0; i < pai; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		sx, sy := priv.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, priv.Params().N)
		vx, vy := priv.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		vx, vy = priv.Add(sx, sy, vx, vy)

		sx, sy = priv.ScalarMult(rx, ry, s.Bytes())
		wx, wy := priv.ScalarMult(QpaiX, QpaiY, c.Bytes())
		wx, wy = priv.Add(sx, sy, wx, wy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, wx, wy)
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

	results[pai+3] = kPai

	return results, nil
}

func (v *BaseLinkableVerfier) Verify(msg []byte, signature []*big.Int) bool {
	pubs := v.publicKeys
	if len(pubs)+3 != len(signature) {
		return false
	}

	rx, ry := publicKeysToPoint(pubs)
	QpaiX := signature[0]
	QpaiY := signature[1]

	c := new(big.Int).Set(signature[2])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+3]

		sx, sy := pub.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, pub.Params().N)
		vx, vy := pub.ScalarMult(pub.X, pub.Y, c.Bytes())
		vx, vy = pub.Add(sx, sy, vx, vy)

		sx, sy = pub.ScalarMult(rx, ry, s.Bytes())
		wx, wy := pub.ScalarMult(QpaiX, QpaiY, c.Bytes())
		wx, wy = pub.Add(sx, sy, wx, wy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, wx, wy)
	}

	return c.Cmp(signature[2]) == 0
}

func Linkable(signature1, signature2 []*big.Int) bool {
	return signature1[0].Cmp(signature2[0]) == 0 && signature1[1].Cmp(signature2[1]) == 0
}

type LinkableVerfierVariant1 struct {
	publicKeys []*ecdsa.PublicKey
}

func NewLinkableVerfierVariant1(pubs []*ecdsa.PublicKey) *LinkableVerfierVariant1 {
	return &LinkableVerfierVariant1{publicKeys: pubs}
}

type LinkableSignerVariant1 struct {
	LinkableVerfierVariant1
	privateKey *sm2.PrivateKey
}

func NewLinkableSignerVariant1(privateKey *sm2.PrivateKey, pubs []*ecdsa.PublicKey) *LinkableSignerVariant1 {
	return &LinkableSignerVariant1{privateKey: privateKey, LinkableVerfierVariant1: LinkableVerfierVariant1{publicKeys: pubs}}
}

func (signer *LinkableSignerVariant1) Sign(rand io.Reader, participantRandInt ParticipantRandInt, msg []byte) ([]*big.Int, error) {
	priv := signer.privateKey
	pubs := signer.publicKeys

	n := len(pubs)
	pai, err := getPai(priv, pubs)
	if err != nil {
		return nil, err
	}

	// step 1, Qpai
	rx, ry := publicKeysToPoint(pubs)
	QpaiX, QpaiY := priv.ScalarMult(rx, ry, priv.D.Bytes())

	rx, ry = priv.Add(rx, ry, priv.Params().Gx, priv.Params().Gy)

	// step 2,
	kPai, err := randFieldElement(priv, rand)
	if err != nil {
		return nil, err
	}

	krx, kry := priv.ScalarMult(rx, ry, kPai.Bytes())
	c := hash1(pubs, QpaiX, QpaiY, msg, krx, kry, nil, nil)

	results := make([]*big.Int, n+3)
	results[0] = QpaiX
	results[1] = QpaiY
	// Step 3
	// [pai+1, ... n)
	for i := pai + 1; i < n; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		c.Add(s, c)
		c.Mod(c, priv.Params().N)

		vx, vy := priv.Add(pubs[i].X, pubs[i].Y, QpaiX, QpaiY)
		vx, vy = priv.ScalarMult(vx, vy, c.Bytes())

		sx, sy := priv.ScalarMult(rx, ry, s.Bytes())
		vx, vy = priv.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, nil, nil)
	}
	results[2] = new(big.Int).Set(c)
	// [0...pai)
	for i := 0; i < pai; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		c.Add(s, c)
		c.Mod(c, priv.Params().N)

		vx, vy := priv.Add(pubs[i].X, pubs[i].Y, QpaiX, QpaiY)
		vx, vy = priv.ScalarMult(vx, vy, c.Bytes())

		sx, sy := priv.ScalarMult(rx, ry, s.Bytes())
		vx, vy = priv.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, nil, nil)
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

	results[pai+3] = kPai

	return results, nil
}

func (v *LinkableSignerVariant1) Verify(msg []byte, signature []*big.Int) bool {
	pubs := v.publicKeys
	if len(pubs)+3 != len(signature) {
		return false
	}

	rx, ry := publicKeysToPoint(pubs)
	rx, ry = pubs[0].Add(rx, ry, pubs[0].Params().Gx, pubs[0].Params().Gy)
	QpaiX := signature[0]
	QpaiY := signature[1]

	c := new(big.Int).Set(signature[2])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+3]

		c.Add(s, c)
		c.Mod(c, pub.Params().N)

		vx, vy := pub.Add(pub.X, pub.Y, QpaiX, QpaiY)
		vx, vy = pub.ScalarMult(vx, vy, c.Bytes())

		sx, sy := pub.ScalarMult(rx, ry, s.Bytes())
		vx, vy = pub.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, vx, vy, nil, nil)
	}

	return c.Cmp(signature[2]) == 0
}

type LinkableVerfierVariant2 struct {
	publicKeys []*ecdsa.PublicKey
}

func NewLinkableVerfierVariant2(pubs []*ecdsa.PublicKey) *LinkableVerfierVariant1 {
	return &LinkableVerfierVariant1{publicKeys: pubs}
}

type LinkableSignerVariant2 struct {
	LinkableVerfierVariant2
	privateKey *sm2.PrivateKey
}

func NewLinkableSignerVariant2(privateKey *sm2.PrivateKey, pubs []*ecdsa.PublicKey) *LinkableSignerVariant1 {
	return &LinkableSignerVariant1{privateKey: privateKey, LinkableVerfierVariant1: LinkableVerfierVariant1{publicKeys: pubs}}
}

func (signer *LinkableSignerVariant2) Sign(rand io.Reader, participantRandInt ParticipantRandInt, msg []byte) ([]*big.Int, error) {
	priv := signer.privateKey
	pubs := signer.publicKeys

	n := len(pubs)
	pai, err := getPai(priv, pubs)
	if err != nil {
		return nil, err
	}

	// step 1, Qpai
	rx, ry := publicKeysToPoint(pubs)
	QpaiX, QpaiY := priv.ScalarMult(rx, ry, priv.D.Bytes())

	rx, ry = priv.Add(rx, ry, priv.Params().Gx, priv.Params().Gy)

	// step 2,
	kPai, err := randFieldElement(priv, rand)
	if err != nil {
		return nil, err
	}

	krx, _ := priv.ScalarMult(rx, ry, kPai.Bytes())
	c := hash1(pubs, QpaiX, QpaiY, msg, nil, nil, nil, nil)
	c.Add(krx, c)
	c.Mod(c, priv.Params().N)

	results := make([]*big.Int, n+3)
	results[0] = QpaiX
	results[1] = QpaiY
	// Step 3
	// [pai+1, ... n)
	for i := pai + 1; i < n; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		c.Add(s, c)
		c.Mod(c, priv.Params().N)

		vx, vy := priv.Add(pubs[i].X, pubs[i].Y, QpaiX, QpaiY)
		vx, vy = priv.ScalarMult(vx, vy, c.Bytes())

		sx, sy := priv.ScalarMult(rx, ry, s.Bytes())
		vx, _ = priv.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, nil, nil, nil, nil)
		c.Add(vx, c)
		c.Mod(c, priv.Params().N)
	}
	results[2] = new(big.Int).Set(c)
	// [0...pai)
	for i := 0; i < pai; i++ {
		s, err := participantRandInt(rand, pubs[i], msg)
		if err != nil {
			return nil, err
		}
		results[i+3] = s
		c.Add(s, c)
		c.Mod(c, priv.Params().N)

		vx, vy := priv.Add(pubs[i].X, pubs[i].Y, QpaiX, QpaiY)
		vx, vy = priv.ScalarMult(vx, vy, c.Bytes())

		sx, sy := priv.ScalarMult(rx, ry, s.Bytes())
		vx, _ = priv.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, nil, nil, nil, nil)
		c.Add(vx, c)
		c.Mod(c, priv.Params().N)
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

	results[pai+3] = kPai

	return results, nil
}

func (v *LinkableSignerVariant2) Verify(msg []byte, signature []*big.Int) bool {
	pubs := v.publicKeys
	if len(pubs)+3 != len(signature) {
		return false
	}

	rx, ry := publicKeysToPoint(pubs)
	rx, ry = pubs[0].Add(rx, ry, pubs[0].Params().Gx, pubs[0].Params().Gy)
	QpaiX := signature[0]
	QpaiY := signature[1]

	c := new(big.Int).Set(signature[2])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+3]

		c.Add(s, c)
		c.Mod(c, pub.Params().N)

		vx, vy := pub.Add(pub.X, pub.Y, QpaiX, QpaiY)
		vx, vy = pub.ScalarMult(vx, vy, c.Bytes())

		sx, sy := pub.ScalarMult(rx, ry, s.Bytes())
		vx, _ = pub.Add(sx, sy, vx, vy)

		c = hash1(pubs, QpaiX, QpaiY, msg, nil, nil, nil, nil)
		c.Add(vx, c)
		c.Mod(c, pub.Params().N)
	}

	return c.Cmp(signature[2]) == 0
}
