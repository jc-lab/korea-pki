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

package korea_pki_core

import (
	api2 "github.com/jc-lab/korea-pki/api"
	"io"
)

type Core interface {
	io.Closer
	LicenseApply(params *api2.LicenseApplyParams) error
	LicenseGet() (*api2.ReturnLicenseInfo, error)
	CertutilPkcs8Decrypt(params *api2.CertutilPkcs8DecryptParams) (*api2.ReturnByteArray, error)
	Anysign4GenerateVidMsg(params *api2.VidMsgParams) (*api2.ReturnByteArray, error)
}
