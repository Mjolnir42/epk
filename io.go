/*-
 * Copyright (c) 2016, Jörg Pernfuß
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package epk // import "github.com/mjolnir42/epk"

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// ReadFrom reconstructs EncryptedPrivateKey from line data read
// in from r. Comment lines starting with a '#' as well as lines
// that are empty or only contain whitespace are skipped.
// The first non-skipped line is expected to be the output of
// Armor() on a single line, surrounding whitespace is ignored.
// Additional lines are ignored.
//
// ReadFrom returns io.ErrUnexpectedEOF if no data line could be
// found as well as any error that occurred.
func ReadFrom(r io.Reader) (*EncryptedPrivateKey, error) {
	// read the Reader into the buffer
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	// scan by line through the buffer
	var data []byte
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Bytes()
		// ignore comment lines
		if strings.HasPrefix(string(line), `#`) {
			continue
		}
		// strip all whitespace from the line
		line = bytes.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, line)
		// ignore lines that were empty or became so
		// by stripping whitespace
		if len(line) == 0 {
			continue
		}
		// copy out the found data line and break the loop
		data = make([]byte, len(line))
		copy(data, line)
		break
	}
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	// decode base64 data
	//
	// golint complains about the else block, but I am unwilling to
	// extend l, err scope outside of the if block
	rawData := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	if l, err := base64.StdEncoding.Decode(rawData, data); err != nil {
		return nil, err
	} else {
		// Decode may use less then what DecodedLen estimates, cut
		// the slice to what was really used
		rawData = rawData[:l]
	}

	// decode the binary gob data stream into the object
	buf = bytes.NewBuffer(rawData)
	decoder := gob.NewDecoder(buf)
	encPK := new(EncryptedPrivateKey)
	if err := decoder.Decode(encPK); err != nil {
		return nil, err
	}
	return encPK, nil
}

// Store writes out the encrypted private key to w in a format suitable
// for import by ReadFrom.
func (e *EncryptedPrivateKey) Store(w io.Writer) error {
	var err error
	var export string

	// write out a comment line indicating what this hunk of base64
	// actually is
	if _, err = fmt.Fprintln(w,
		`# encrypted Ed25519 private key, github.com/mjolnir42/epk`,
	); err != nil {
		return err
	}

	if export, err = e.Armor(); err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, export)
	return err
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
