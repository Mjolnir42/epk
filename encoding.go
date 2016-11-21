/*-
 * Copyright (c) 2016, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package epk

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
)

// Armor returns the ascii armored binary serialization of e.
// The ASCII armor is encoded using standard base64.
func (e *EncryptedPrivateKey) Armor() (string, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(e); err != nil {
		return ``, err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// GobEncode implements the gob.GobEncoder interface
func (e *EncryptedPrivateKey) GobEncode() ([]byte, error) {
	var err error
	w := new(bytes.Buffer)
	encoder := gob.NewEncoder(w)

	if err = encoder.Encode(e.Keytype); err != nil {
		return nil, err
	}
	if err = encoder.Encode(e.KDF); err != nil {
		return nil, err
	}
	if err = encoder.Encode(e.KDFParam); err != nil {
		return nil, err
	}
	if err = encoder.Encode(e.Salt); err != nil {
		return nil, err
	}
	if err = encoder.Encode(e.privateKey); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface
func (e *EncryptedPrivateKey) GobDecode(buf []byte) error {
	var err error
	r := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(r)

	if err = decoder.Decode(&e.Keytype); err != nil {
		return err
	}
	if err = decoder.Decode(&e.KDF); err != nil {
		return err
	}
	if err = decoder.Decode(&e.KDFParam); err != nil {
		return err
	}
	if err = decoder.Decode(&e.Salt); err != nil {
		return err
	}
	return decoder.Decode(&e.privateKey)
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
