package api

import "github.com/jc-lab/jclab-license/license_model"

//go:generate msgp

type LicenseApplyParams struct {
	LicenseCode string `msg:"licenseCode"`
}

type ReturnLicenseInfo struct {
	LibraryLicenseVersion int    `msg:"libraryLicenseVersion"`
	LibraryVersion        string `msg:"libraryVersion"`
	LibraryCommitHash     string `msg:"libraryCommitHash"`
	LibraryBuildTimestamp string `msg:"libraryBuildTimestamp"`

	LicensesDocument string `msg:"licensesDocument"`

	Success        bool                  `msg:"success"`
	ErrorMessage   string                `msg:"errorMessage"`
	AppliedLicense *license_model.Claims `msg:"appliedLicense"`
}
