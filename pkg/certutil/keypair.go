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
	"crypto"
	"crypto/x509"
	"github.com/jc-lab/korea-pki/internal/kx509"
	"github.com/jc-lab/korea-pki/pkg/korea_pki_core"
	"github.com/pkg/errors"
	"path/filepath"
)

type CertFile struct {
	// First
	CertDer []byte
	KeyDer  []byte

	// Secondary
	Directory string

	// Third
	CertFile string
	KeyFile  string

	Password string
}

type KeyPair struct {
	Certificate          *x509.Certificate
	PrivateKey           crypto.PrivateKey
	PrivateKeyAttributes Attributes
}

func LoadKeyPair(core korea_pki_core.Core, certFile *CertFile) (*KeyPair, error) {
	var err error
	output := &KeyPair{}

	if certFile.CertDer != nil {
		if output.Certificate, err = kx509.ParseCertificate(certFile.CertDer); err != nil {
			return nil, err
		}
	} else if certFile.CertFile != "" {
		if output.Certificate, err = LoadX509File(certFile.CertFile); err != nil {
			return nil, err
		}
	} else if certFile.Directory != "" {
		if output.Certificate, err = LoadX509File(filepath.Join(certFile.Directory, "signCert.der")); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("no certificate")
	}

	if certFile.KeyDer != nil {
		if output.PrivateKey, output.PrivateKeyAttributes, err = ReadEncryptedPrivateKey(core, certFile.KeyDer, certFile.Password); err != nil {
			return nil, err
		}
	} else if certFile.KeyFile != "" {
		if output.PrivateKey, output.PrivateKeyAttributes, err = LoadPrivateKeyFile(core, certFile.KeyFile, certFile.Password); err != nil {
			return nil, err
		}
	} else if certFile.Directory != "" {
		if output.PrivateKey, output.PrivateKeyAttributes, err = LoadPrivateKeyFile(core, filepath.Join(certFile.Directory, "signPri.key"), certFile.Password); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("no certificate")
	}

	return output, nil
}
