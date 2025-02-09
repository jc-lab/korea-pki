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
	"crypto/x509"
	"github.com/jc-lab/korea-pki/internal/kx509"
	"github.com/pkg/errors"
)

func LoadX509File(file string) (*x509.Certificate, error) {
	block, err := LoadFileAsPemOrDer(file)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate file failed")
	}

	certificate, err := kx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate der failed")
	}
	return certificate, nil
}
