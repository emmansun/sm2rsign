package sm2rsign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func testBaseLRSignWithTwoKeys(t *testing.T, participantRandInt ParticipantRandInt) {
	signer, _ := sm2.GenerateKey(rand.Reader)
	participant, _ := sm2.GenerateKey((rand.Reader))
	pubs := []*ecdsa.PublicKey{&signer.PublicKey, &participant.PublicKey}
	msg1 := []byte("hello world")
	msg2 := []byte("World Peace")

	baseSigner := NewBaseLinkableSigner(signer, pubs)

	sig1, err := baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}

	pubs[0] = &participant.PublicKey
	pubs[1] = &signer.PublicKey

	sig1, err = baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err = baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}
}

func TestBaseLRSignWithTwoKeys(t *testing.T) {
	testBaseLRSignWithTwoKeys(t, SimpleParticipantRandInt)
	testBaseLRSignWithTwoKeys(t, SM2ParticipantRandInt)
}

func testLRSignVariant1WithTwoKeys(t *testing.T, participantRandInt ParticipantRandInt) {
	signer, _ := sm2.GenerateKey(rand.Reader)
	participant, _ := sm2.GenerateKey((rand.Reader))
	pubs := []*ecdsa.PublicKey{&signer.PublicKey, &participant.PublicKey}
	msg1 := []byte("hello world")
	msg2 := []byte("World Peace")

	baseSigner := NewLinkableSignerVariant1(signer, pubs)

	sig1, err := baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}

	pubs[0] = &participant.PublicKey
	pubs[1] = &signer.PublicKey

	sig1, err = baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err = baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}
}

func TestLRSignVariant1WithTwoKeys(t *testing.T) {
	testLRSignVariant1WithTwoKeys(t, SimpleParticipantRandInt)
	testLRSignVariant1WithTwoKeys(t, SM2ParticipantRandInt)
}

func testLRSignVariant2WithTwoKeys(t *testing.T, participantRandInt ParticipantRandInt) {
	signer, _ := sm2.GenerateKey(rand.Reader)
	participant, _ := sm2.GenerateKey((rand.Reader))
	pubs := []*ecdsa.PublicKey{&signer.PublicKey, &participant.PublicKey}
	msg1 := []byte("hello world")
	msg2 := []byte("World Peace")

	baseSigner := NewLinkableSignerVariant2(signer, pubs)

	sig1, err := baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}

	pubs[0] = &participant.PublicKey
	pubs[1] = &signer.PublicKey

	sig1, err = baseSigner.Sign(rand.Reader, participantRandInt, msg1)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err = baseSigner.Sign(rand.Reader, participantRandInt, msg2)
	if err != nil {
		t.Fatal(err)
	}

	if !baseSigner.Verify(msg1, sig1) {
		t.Errorf("failed to verify the signature")
	}

	if !baseSigner.Verify(msg2, sig2) {
		t.Errorf("failed to verify the signature")
	}

	if !Linkable(sig1, sig2) {
		t.Errorf("failed to link")
	}
}

func TestLRSignVariant2WithTwoKeys(t *testing.T) {
	testLRSignVariant2WithTwoKeys(t, SimpleParticipantRandInt)
	testLRSignVariant2WithTwoKeys(t, SM2ParticipantRandInt)
}
