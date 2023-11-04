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
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/jc-lab/korea-pki/api"
	"github.com/jc-lab/korea-pki/pkg/korea_pki_core"
	"github.com/pkg/errors"
	"os"
)

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value []asn1.RawValue `asn1:"set"`
}

type Attributes []Attribute

// Pkcs8Asn reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type Pkcs8Asn struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []Attribute `asn1:"tag:0,set,optional"`
}

func ReadEncryptedPrivateKey(core korea_pki_core.Core, der []byte, passphrase string) (crypto.PrivateKey, Attributes, error) {
	res, err := core.CertutilPkcs8Decrypt(&api.CertutilPkcs8DecryptParams{
		Input:    der,
		Password: []byte(passphrase),
	})
	if err != nil {
		return nil, nil, err
	}
	return parsePkcs8PrivateKey(res.Data)
}

func LoadPrivateKeyFile(core korea_pki_core.Core, file string, passphrase string) (crypto.PrivateKey, Attributes, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	block, err := LoadPemOrDer(content)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse certificate file failed")
	}
	return ReadEncryptedPrivateKey(core, block.Bytes, passphrase)
}

func parsePkcs8PrivateKey(decryptedKey []byte) (crypto.PrivateKey, Attributes, error) {
	var pkcs8Key Pkcs8Asn
	_, _ = asn1.Unmarshal(decryptedKey, &pkcs8Key)
	key, err := x509.ParsePKCS8PrivateKey(decryptedKey)
	if err != nil {
		return nil, nil, errors.New("pkcs8: incorrect password")
	}
	return key, pkcs8Key.Attributes, nil
}
