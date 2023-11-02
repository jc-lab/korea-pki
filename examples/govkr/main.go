package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"flag"
	korea_pki "github.com/jc-lab/korea-pki"
	"github.com/jc-lab/korea-pki/api"
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
	"strings"
)

//go:embed SVR1741597001.der
var govKrCert []byte

func main() {
	var certDir string
	flag.StringVar(&certDir, "certdir", "", "Certificate Directory (e.g. C:/Users/User/AppData/LocalLow/NPKI/KICA/USER/...")
	flag.Parse()

	if certDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	core, err := korea_pki.New(context.Background())
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

	if login(core, client, keyPair) {
		simpleGet(client)
	}
}

func login(core korea_pki_core.Core, client *http.Client, keyPair *certutil.KeyPair) bool {
	npkiRandomNum, err := sign.GetNpkiRandomNum(keyPair)
	if err != nil {
		log.Fatalln(err)
	}

	signed, err := sign.Sign(keyPair, []byte([]byte{0xb0, 0xf8, 0xb5, 0xbf, 0xc0, 0xce, 0xc1, 0xf5, 0xbc, 0xad, 0xb7, 0xce, 0xb1, 0xd7, 0xc0, 0xce}))
	if err != nil {
		log.Fatalln(err)
	}

	vidMsgRes, err := core.Anysign4GenerateVidMsg(&api.VidMsgParams{
		Input:         "",
		NpkiRandomNum: npkiRandomNum,
		ServerCert:    govKrCert,
	})
	if err != nil {
		log.Fatalln(err)
	}

	data := url.Values{}
	data.Set("a", "/nlogin/loginByIdPwd")
	data.Set("vidMsg", hex.EncodeToString(vidMsgRes.Data))
	data.Set("xml", hex.EncodeToString(signed))
	data.Set("pkcs1Msg", hex.EncodeToString(signed))
	data.Set("currUrl", "")
	data.Set("randomnum", "")
	data.Set("loginType", "browserLogin")
	data.Set("certiType", "")
	data.Set("certiType2", "")
	data.Set("browserYn", "Y")
	data.Set("regYn", "")
	data.Set("isTouchYn", "")
	data.Set("loginGb", "")
	data.Set("loginFlag", "")
	data.Set("cdFlag", "")
	data.Set("dynaPathVer", "N/A")

	req, err := http.NewRequest("POST", "https://www.gov.kr/nlogin/loginByIdPwd", bytes.NewReader([]byte(data.Encode())))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://www.gov.kr/nlogin/?Mcode=10003&regType=ctab")
	req.Header.Set("Origin", "https://www.gov.kr")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")

	res, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	if res.StatusCode != 302 {
		log.Printf("invalid status code: %d", res.StatusCode)
		return false
	}

	location := res.Header.Get("location")
	if location == "https://www.gov.kr/portal/main" {
		log.Println("LOGIN SUCCESS!!!")
		return true
	} else {
		log.Printf("LOGIN FAILED!!! location: %s", location)
		return false
	}
}

func simpleGet(client *http.Client) {
	req, err := http.NewRequest("GET", "https://www.gov.kr/portal/main", nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Referer", "https://www.gov.kr/nlogin/loginByIdPwd")
	req.Header.Set("Origin", "https://www.gov.kr")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")

	res, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}

	bodyStr := string(body)
	lines := strings.Split(bodyStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "var userNm =") {
			log.Println(line)
		}
	}
}
