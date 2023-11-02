package korea_pki

import (
	"context"
	"github.com/jc-lab/korea-pki/internal/core_wasm"
	"github.com/jc-lab/korea-pki/pkg/korea_pki_core"
)

func New(ctx context.Context) (korea_pki_core.Core, error) {
	return core_wasm.New(ctx)
}
