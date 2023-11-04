// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.
//
// https://github.com/jc-lab/license-terms/blob/master/dual-license-commercial-or-ssplv1/README.md
//
// Licensed under the JC-Lab License 1.0 and the Server Side Public License,
// v1; you may not use this file except in compliance with, at your election,
// the JC-Lab License 1.0 or the Server Side Public License, v1.

package certutil

import (
	"bytes"
	"encoding/pem"
	"github.com/pkg/errors"
	"os"
)

func LoadPemOrDer(content []byte) (*pem.Block, error) {
	var textStart int = 0
	for (content[textStart] == 0x20) || (content[textStart] == '\r') || (content[textStart] == '\n') || (content[textStart] == '\t') {
		textStart++
	}
	textContent := content[textStart:]

	if bytes.Index(textContent, []byte("-----BEGIN")) >= 0 {
		block, _ := pem.Decode(textContent)
		if block == nil {
			return nil, errors.New("parse pem failed")
		}
		return block, nil
	}

	return &pem.Block{
		Bytes: content,
	}, nil
}

func LoadFileAsPemOrDer(file string) (*pem.Block, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return LoadPemOrDer(content)
}
