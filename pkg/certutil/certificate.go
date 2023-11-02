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
	"crypto/x509"
	"github.com/pkg/errors"
)

func LoadX509File(file string) (*x509.Certificate, error) {
	block, err := LoadFileAsPemOrDer(file)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate file failed")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate der failed")
	}
	return certificate, nil
}
