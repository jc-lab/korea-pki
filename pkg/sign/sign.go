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

package sign

import (
	"encoding/asn1"
	"github.com/jc-lab/korea-pki/pkg/certutil"
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
