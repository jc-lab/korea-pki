// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.
//
// https://github.com/jc-lab/license-terms/blob/master/dual-license-commercial-or-ssplv1/README.md
//
// Licensed under the JC-Lab License 1.0 and the Server Side Public License,
// v1; you may not use this file except in compliance with, at your election,
// the JC-Lab License 1.0 or the Server Side Public License, v1.

package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"github.com/jc-lab/korea-pki/pkg/certutil"
	"github.com/pkg/errors"
	"go.mozilla.org/pkcs7"
)

func GetNpkiRandomNum(keyPair *certutil.KeyPair) ([]byte, error) {
	for _, attribute := range keyPair.PrivateKeyAttributes {
		if attribute.Type.String() == "1.2.410.200004.10.1.1.3" {
			var value asn1.BitString
			if _, err := asn1.Unmarshal(attribute.Value[0].FullBytes, &value); err != nil {
				return nil, err
			}
			return value.Bytes, nil
		}
	}
	return nil, nil
}

func Sign(keyPair *certutil.KeyPair, data []byte) ([]byte, error) {
	signedData, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, err
	}
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signedData.AddSigner(keyPair.Certificate, keyPair.PrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return signedData.Finish()
}

func SignPKCS1v15(keyPair *certutil.KeyPair, hash crypto.Hash, message []byte) ([]byte, error) {
	privateKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("no rsa key")
	}
	h := hash.New()
	h.Write(message)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
}
