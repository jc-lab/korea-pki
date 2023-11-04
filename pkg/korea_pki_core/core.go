// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.
//
// https://github.com/jc-lab/license-terms/blob/master/dual-license-commercial-or-ssplv1/README.md
//
// Licensed under the JC-Lab License 1.0 and the Server Side Public License,
// v1; you may not use this file except in compliance with, at your election,
// the JC-Lab License 1.0 or the Server Side Public License, v1.

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
