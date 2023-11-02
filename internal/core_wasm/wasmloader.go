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

package core_wasm

import (
	"context"
	_ "embed"
	"github.com/jc-lab/korea-pki/api"
	"github.com/jc-lab/korea-pki/pkg/korea_pki_core"
	"github.com/pkg/errors"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tinylib/msgp/msgp"
)

type wasmCore struct {
	ctx context.Context
	r   wazero.Runtime
	m   wapi.Module
}

// mainWasmBinary 해당 파일 또한 AGPLv3 으로 배포됩니다.
// 해당 바이너리를 사용할 경우 사용하는 소프트웨어에 AGPLv3 호환 라이선스를 적용해야 합니다.
//
//go:embed main.wasm
var mainWasmBinary []byte

func New(ctx context.Context) (korea_pki_core.Core, error) {
	c := &wasmCore{
		ctx: ctx,
		r:   wazero.NewRuntime(ctx),
	}

	compiledModule, err := c.r.CompileModule(c.ctx, mainWasmBinary)
	if err != nil {
		panic(err)
	}

	_, err = wasi_snapshot_preview1.Instantiate(c.ctx, c.r)
	if err != nil {
		panic(err)
	}

	c.m, err = c.r.InstantiateModule(c.ctx, compiledModule, wazero.NewModuleConfig())
	if err != nil {
		panic(err)
	}

	return c, nil
}

func (c *wasmCore) Close() error {
	return c.r.Close(c.ctx)
}

func (c *wasmCore) LicenseApply(params *api.LicenseApplyParams) error {
	fn := c.m.ExportedFunction("licenseApply")
	if fn == nil {
		return errors.New("no licenseApply function")
	}
	r := new(api.ReturnError)
	if err := c.call(fn, params, r); err != nil {
		return err
	}
	return apiReturnErrorToError(r)
}

func (c *wasmCore) LicenseGet() (*api.ReturnLicenseInfo, error) {
	fn := c.m.ExportedFunction("licenseGet")
	if fn == nil {
		return nil, errors.New("no licenseGet function")
	}
	r := new(api.ReturnLicenseInfo)
	if err := c.call(fn, nil, r); err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, korea_pki_core.NewError(r, r.ErrorMessage)
	}
	return r, nil
}

func (c *wasmCore) CertutilPkcs8Decrypt(params *api.CertutilPkcs8DecryptParams) (*api.ReturnByteArray, error) {
	fn := c.m.ExportedFunction("certutilPkcs8Decrypt")
	if fn == nil {
		return nil, errors.New("no certutilPkcs8Decrypt function")
	}
	r := new(api.ReturnByteArray)
	if err := c.call(fn, params, r); err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, korea_pki_core.NewError(r, r.ErrorMessage)
	}
	return r, nil
}

func (c *wasmCore) Anysign4GenerateVidMsg(params *api.VidMsgParams) (*api.ReturnByteArray, error) {
	fn := c.m.ExportedFunction("anysign4GenerateVidMsg")
	if fn == nil {
		return nil, errors.New("no anysign4GenerateVidMsg function")
	}
	r := new(api.ReturnByteArray)
	if err := c.call(fn, params, r); err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, korea_pki_core.NewError(r, r.ErrorMessage)
	}
	return r, nil
}

func (c *wasmCore) malloc(size int) (uint64, error) {
	fn := c.m.ExportedFunction("malloc")
	if fn == nil {
		return 0, errors.New("no malloc function")
	}
	returns, err := fn.Call(c.ctx, uint64(size))
	if err != nil {
		return 0, err
	}
	return returns[0], nil
}

func (c *wasmCore) free(ptr uint64) error {
	fn := c.m.ExportedFunction("free")
	if fn == nil {
		return errors.New("no malloc function")
	}
	returns, err := fn.Call(c.ctx, uint64(ptr))
	if err != nil {
		return err
	}
	_ = returns
	return nil
}

func (c *wasmCore) mallocData(data []byte) (uint64, error) {
	ptr, err := c.malloc(len(data))
	if err != nil {
		return 0, err
	}
	if !c.m.Memory().Write(uint32(ptr), data) {
		c.free(ptr)
		return 0, errors.New("error")
	}
	return ptr, nil
}

func (c *wasmCore) refFree(ptr uint32) error {
	fn := c.m.ExportedFunction("goRefFree")
	if fn == nil {
		return errors.New("no goRefFree function")
	}
	returns, err := fn.Call(c.ctx, uint64(ptr))
	if err != nil {
		return err
	}
	_ = returns
	return nil
}

func (c *wasmCore) readReturnDataAndFree(ret uint64) ([]byte, error) {
	ptr, size := parseReturn(ret)
	defer c.refFree(ptr)
	data, ok := c.m.Memory().Read(ptr, size)
	if !ok {
		return nil, errors.New("error")
	}
	return data, nil
}

func (c *wasmCore) call(fn wapi.Function, params msgp.Marshaler, returnParams msgp.Unmarshaler) error {
	var returns []uint64
	var rootErr error
	if params != nil {
		paramsRaw, err := params.MarshalMsg(nil)
		if err != nil {
			return err
		}
		paramsPtr, err := c.mallocData(paramsRaw)
		if err != nil {
			return err
		}
		defer c.free(paramsPtr)
		returns, rootErr = fn.Call(c.ctx, paramsPtr, uint64(len(paramsRaw)))
	} else {
		returns, rootErr = fn.Call(c.ctx)
	}
	if rootErr != nil {
		return rootErr
	}
	data, err := c.readReturnDataAndFree(returns[0])
	if err != nil {
		return err
	}
	_, err = returnParams.UnmarshalMsg(data)
	return err
}

func parseReturn(input uint64) (ptr uint32, size uint32) {
	return uint32(input >> 32), uint32(input)
}

func apiReturnErrorToError(r *api.ReturnError) error {
	if !r.Success {
		return korea_pki_core.NewError(r, r.ErrorMessage)
	}
	return nil
}
