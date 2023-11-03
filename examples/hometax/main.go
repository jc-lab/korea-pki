package main

import (
	"bytes"
	"context"
	"crypto"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"github.com/davecgh/go-spew/spew"
	govkr2 "github.com/jc-lab/korea-pki/internal/core_wasm"
	"github.com/jc-lab/korea-pki/pkg/certutil"
	"github.com/jc-lab/korea-pki/pkg/cmdutil"
	"github.com/jc-lab/korea-pki/pkg/korea_pki_core"
	"github.com/jc-lab/korea-pki/pkg/sign"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
)

func main() {
	var certDir string
	flag.StringVar(&certDir, "certdir", "", "Certificate Directory (e.g. C:/Users/User/AppData/LocalLow/NPKI/KICA/USER/...")
	flag.Parse()

	if certDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	core, err := govkr2.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	defer core.Close()

	password, err := cmdutil.EnterPassword("Enter Certificate Password: ")
	if err != nil {
		log.Fatal(err)
	}

	// 공동인증서로그인
	keyPair, err := certutil.LoadKeyPair(core, &certutil.CertFile{
		Directory: certDir,
		Password:  password,
	})
	if err != nil {
		log.Fatal(err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Jar:       jar,
		Transport: http.DefaultTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if !login(core, client, keyPair) {
		return
	}

	data, err := simpleGetXml(client, "https://www.hometax.go.kr/permission.do?screenId=index_pp", `<map id='postParam'><popupYn>false</popupYn></map>`)
	if err != nil {
		log.Fatalln(err)
	}

	var loginPp PermissionLoginPpResp
	if err = xml.Unmarshal(data, &loginPp); err != nil {
		log.Fatalln(err)
	}

	spew.Dump(loginPp)
}

func login(core korea_pki_core.Core, client *http.Client, keyPair *certutil.KeyPair) bool {
	npkiRandomNum, err := sign.GetNpkiRandomNum(keyPair)
	if err != nil {
		log.Fatalln(err)
	}

	pkcEncSsn, err := fetchPkcEncSsn(client)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("pkcEncSsn: ", pkcEncSsn)

	signed, err := sign.SignPKCS1v15(keyPair, crypto.SHA256, []byte(pkcEncSsn))
	if err != nil {
		log.Fatalln(err)
	}

	logSgnt, err := makeLogSgnt(keyPair, pkcEncSsn, signed)
	if err != nil {
		log.Fatalln(err)
	}

	certificatePem := pem.EncodeToMemory(&pem.Block{
		Bytes: keyPair.Certificate.Raw,
		Type:  "CERTIFICATE",
	})

	data := url.Values{}
	data.Set("logSgnt", logSgnt)
	data.Set("cert", string(certificatePem))
	data.Set("randomEnc", base64.StdEncoding.EncodeToString(npkiRandomNum))
	data.Set("pkcLoginYnImpv", "Y")
	data.Set("pkcLgnClCd", "03")
	data.Set("ssoStatus", "")
	data.Set("portalStatus", "")
	data.Set("scrnId", "UTXPPABA01")
	data.Set("userScrnRslnXcCnt", "1451")
	data.Set("userScrnRslnYcCnt", "907")

	req, err := http.NewRequest("POST", "https://www.hometax.go.kr/pubcLogin.do?domain=hometax.go.kr&mainSys=Y", bytes.NewReader([]byte(data.Encode())))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.hometax.go.kr")
	req.Header.Set("Referer", "https://www.hometax.go.kr/websquare/websquare.wq?w2xPath=/ui/comm/a/b/UTXPPABA01.xml&w2xHome=/ui/pp/&w2xDocumentRoot=")

	res, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	if res.StatusCode != 200 {
		log.Printf("invalid status code: %d", res.StatusCode)
		return false
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}

	loginResult := parseLoginResult(string(body))
	if loginResult.Code != "S" {
		log.Println("LOGIN FAILED: " + loginResult.ErrMsg)
		return false
	}

	log.Println("LOGIN SUCCESS")

	return true
}
