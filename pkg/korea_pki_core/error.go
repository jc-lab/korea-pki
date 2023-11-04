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

type CoreError struct {
	Raw     interface{}
	message string
}

func NewError(Raw interface{}, message string) *CoreError {
	return &CoreError{
		Raw:     Raw,
		message: message,
	}
}

func (c *CoreError) Error() string {
	return c.message
}
