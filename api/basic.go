// korea-pki
//
// Copyright (C) 2023 JC-Lab. All rights reserved.

package api

import (
	"github.com/tinylib/msgp/msgp"
	"unsafe"
)

//go:generate msgp

type ReturnError struct {
	Success      bool   `msg:"success"`
	ErrorMessage string `msg:"errorMessage"`
}

type ReturnByteArray struct {
	Success      bool   `msg:"success"`
	ErrorMessage string `msg:"errorMessage"`
	Data         []byte `msg:"data"`
}

func bridgeEncode(data msgp.Marshaler) []byte {
	encoded, err := data.MarshalMsg(nil)
	if err != nil {
		panic(err)
	}
	return encoded
}

func WasmUnmarshalParam(param msgp.Unmarshaler, ptr *byte, size int) error {
	paramRaw := unsafe.Slice(ptr, size)
	_, err := param.UnmarshalMsg(paramRaw)
	return err
}

func WasmReturnError(err error) []byte {
	r := &ReturnError{
		Success: err == nil,
	}
	if err != nil {
		r.ErrorMessage = err.Error()
	}
	return bridgeEncode(r)
}

func WasmReturnByteArray(data []byte, err error) []byte {
	r := &ReturnByteArray{
		Success: err == nil,
		Data:    data,
	}
	if err != nil {
		r.ErrorMessage = err.Error()
	}
	return bridgeEncode(r)
}

func WasmReturnLicenseInfo(r *ReturnLicenseInfo, err error) []byte {
	r.Success = err == nil
	if err != nil {
		r.ErrorMessage = err.Error()
	}
	return bridgeEncode(r)
}
