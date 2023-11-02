// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.

package api

import (
	"encoding/base64"
)

//go:generate msgp

type VidMsgParams struct {
	Input         string `msg:"input"`
	ServerCert    []byte `msg:"serverCert"`
	NpkiRandomNum []byte `msg:"npkiRandomNum"`
}

func (p *VidMsgParams) FromBase64(input string) error {
	raw, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	_, err = p.UnmarshalMsg(raw)
	return err
}
