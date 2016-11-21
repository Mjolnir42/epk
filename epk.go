/*-
 * Copyright (c) 2016, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

// Package epk implements an encrypted private key
// on top of the Ed25519 signature scheme.
// Given the passphrase and a message it can also
// unlock the key and sign the message.
//
// It uses scrypt as key derivation function and
// ChaCha20/Poly1305 for encryption.
package epk // import "github.com/mjolnir42/epk"

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

// EncryptedPrivateKey implements an encrypted private key
type EncryptedPrivateKey struct {
	// the private key type: Ed25519
	Keytype string
	// the used KDF: scrypt
	KDF string
	// the used KDF parameters: N=65536;r=8;p=1
	KDFParam string
	// the used encryption algorithm: ChaCha20Poly1305
	EncAlgorithm string
	// 24 byte salt for the KDF, 12 of which are also
	// used as AEAD nonce
	Salt []byte
	// the encrypted private key
	privateKey []byte
}

// New returns the public and encrypted private key for
// a generated keypair.
func New(passphrase string) (*EncryptedPrivateKey, ed25519.PublicKey, error) {
	var err error
	var priv, pub []byte
	encPK := new(EncryptedPrivateKey)

	if pub, priv, err = ed25519.GenerateKey(cryptorand.Reader); err != nil {
		return nil, nil, err
	}
	encPK.Keytype = `Ed25519`

	err = encPK.set([]byte(passphrase), priv)
	return encPK, pub, err
}

// Sign signs the message with the private key protected by passphrase
// and returns the signature.
func (e *EncryptedPrivateKey) Sign(passphrase string, message []byte) ([]byte, error) {
	// compute the key to unlock the private key
	key, err := e.derive([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	return e.signMsg(key, message)
}

// set saves the private key after encryption with the passphrase
// as e.privatekey
func (e *EncryptedPrivateKey) set(passphrase, private []byte) error {
	if err := e.newSalt(); err != nil {
		return err
	}

	key, err := e.derive(passphrase)
	if err != nil {
		return err
	}

	if err = e.encrypt(key, private); err != nil {
		return err
	}
	return nil
}

// encrypt encrypts data with key and stored the resulting
// ciphertext in e.privateKey
func (e *EncryptedPrivateKey) encrypt(key, data []byte) error {
	var err error
	var crypt cipher.AEAD

	if crypt, err = chacha20poly1305.New(key); err != nil {
		return err
	}

	e.privateKey = crypt.Seal([]byte{}, e.Salt[:12], data, []byte{})
	e.EncAlgorithm = `ChaCha20Poly1305`
	return nil
}

// derive uses scrypt to generate a key from a passphrase
func (e *EncryptedPrivateKey) derive(passphrase []byte) ([]byte, error) {
	if e.KDF == `` {
		e.KDF = `scrypt`
	}
	if e.KDFParam == `` {
		e.KDFParam = `N=65536;r=8;p=1`
	}

	return scrypt.Key(passphrase, e.Salt, 65536, 8, 1, 32)
}

// newSalt reads a new random salt and stores it in e.Salt
func (e *EncryptedPrivateKey) newSalt() error {
	e.Salt = make([]byte, 24)

	_, err := io.ReadFull(cryptorand.Reader, e.Salt[:24])
	return err
}

// signMsg unlocks the private key and signs message with it. It
// returns the signature.
func (e *EncryptedPrivateKey) signMsg(key, message []byte) ([]byte, error) {
	var err error
	var pk, sig []byte
	var crypt cipher.AEAD

	if crypt, err = chacha20poly1305.New(key); err != nil {
		return nil, err
	}

	if pk, err = crypt.Open([]byte{}, e.Salt[:12],
		e.privateKey, []byte{}); err != nil {
		return nil, err
	}

	sig = ed25519.Sign(pk, message)
	return sig, nil
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
