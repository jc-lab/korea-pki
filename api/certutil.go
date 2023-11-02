package api

//go:generate msgp

type CertutilPkcs8DecryptParams struct {
	Input    []byte `msg:"input"`
	Password []byte `msg:"password"`
}
