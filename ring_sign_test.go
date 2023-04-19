package sm2rsign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func testRSignWithTwoKeys(t *testing.T, participantRandInt ParticipantRandInt) {
	signer, _ := sm2.GenerateKey(rand.Reader)
	participant, _ := sm2.GenerateKey((rand.Reader))
	pubs := []*ecdsa.PublicKey{&signer.PublicKey, &participant.PublicKey}
	msg := []byte("hello world")

	sig, err := Sign(rand.Reader, participantRandInt, signer, pubs, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubs, msg, sig) {
		t.Errorf("failed to verify the signature")
	}

	pubs[0] = &participant.PublicKey
	pubs[1] = &signer.PublicKey
	sig, err = Sign(rand.Reader, participantRandInt, signer, pubs, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubs, msg, sig) {
		t.Errorf("failed to verify the signature")
	}
}

func TestRSignWithTwoKeys(t *testing.T) {
	testRSignWithTwoKeys(t, SimpleParticipantRandInt)
	testRSignWithTwoKeys(t, SM2ParticipantRandInt)
}

func testRSignWithThreeKeys(t *testing.T, participantRandInt ParticipantRandInt) {
	signer, _ := sm2.GenerateKey(rand.Reader)
	participant1, _ := sm2.GenerateKey((rand.Reader))
	participant2, _ := sm2.GenerateKey((rand.Reader))
	pubs := []*ecdsa.PublicKey{&participant1.PublicKey, &signer.PublicKey, &participant2.PublicKey}
	msg := []byte("hello world")

	sig, err := Sign(rand.Reader, participantRandInt, signer, pubs, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubs, msg, sig) {
		t.Errorf("failed to verify the signature")
	}

	pubs[0] = &participant1.PublicKey
	pubs[1] = &participant2.PublicKey
	pubs[2] = &signer.PublicKey
	sig, err = Sign(rand.Reader, participantRandInt, signer, pubs, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubs, msg, sig) {
		t.Errorf("failed to verify the signature")
	}

	pubs[0] = &signer.PublicKey
	pubs[1] = &participant1.PublicKey
	pubs[2] = &participant2.PublicKey

	sig, err = Sign(rand.Reader, participantRandInt, signer, pubs, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubs, msg, sig) {
		t.Errorf("failed to verify the signature")
	}
}

func TestRSign2WithThreeKeys(t *testing.T) {
	testRSignWithThreeKeys(t, SimpleParticipantRandInt)
	testRSignWithThreeKeys(t, SM2ParticipantRandInt)
}
