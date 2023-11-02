// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package certutil

import (
	"crypto"
	"crypto/x509"
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
		if output.Certificate, err = x509.ParseCertificate(certFile.CertDer); err != nil {
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
	} else if certFile.CertFile != "" {
		if output.PrivateKey, output.PrivateKeyAttributes, err = LoadPrivateKeyFile(core, certFile.CertFile, certFile.Password); err != nil {
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
