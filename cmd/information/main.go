package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	korea_pki "github.com/jc-lab/korea-pki"
	"log"
	"os"
)

func main() {
	var flagReleaseInfo bool
	flag.BoolVar(&flagReleaseInfo, "release-info", false, "print only release info as JSON")
	flag.Parse()

	core, err := korea_pki.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	defer core.Close()

	//core.LicenseApply(&api.LicenseApplyParams{
	//	LicenseCode: "여기에 라이선스 코드를 넣으세요",
	//})

	licenseInfo, err := core.LicenseGet()
	if err != nil {
		log.Fatal(err)
	}

	if flagReleaseInfo {
		out, err := json.Marshal(map[string]any{
			"version":        licenseInfo.LibraryVersion,
			"licenseVersion": licenseInfo.LibraryLicenseVersion,
		})
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.WriteString(string(out))
	} else {
		println("라이선스 목록:")
		println(licenseInfo.LicensesDocument)
		println("")

		println("라이브러리 버전: ", licenseInfo.LibraryVersion)
		println("라이브러리 라이선스 버전: ", licenseInfo.LibraryLicenseVersion)

		appliedLicense := licenseInfo.AppliedLicense

		if appliedLicense != nil {
			var licenseMaxVer string
			if appliedLicense.LicenseMaxVersion < 0 {
				licenseMaxVer = "제한 없음"
			} else {
				licenseMaxVer = fmt.Sprintf("%d", appliedLicense.LicenseMaxVersion)
			}
			println("적용된 라이선스 버전 상한 : ", licenseMaxVer)
			println("적용된 라이선스 형태(commercial or opensource) : ", appliedLicense.LicenseType)
			println("적용된 라이선스 제품: ", appliedLicense.Product)
			println("적용된 라이선스 사용자: ", appliedLicense.LicenseeName)
			println("적용된 라이선스 사용자 이메일: ", appliedLicense.LicenseeEmail)
		}
	}
}
