package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"github.com/jc-lab/korea-pki/pkg/certutil"
	"github.com/pkg/errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ActionATXPPZXA001R01Response struct {
	XMLName xml.Name `xml:"map"`
	ID      string   `xml:"id,attr"`
	//Script  string   `xml:"script"`
	Map struct {
		ID        string `xml:"id,attr"`
		DetailMsg string `xml:"detailMsg"`
		Msg       string `xml:"msg"`
		Code      string `xml:"code"`
		Result    string `xml:"result"`
	} `xml:"map"`
	PkcEncSsn string `xml:"pkcEncSsn"`
}

func fetchPkcEncSsn(client *http.Client) (string, error) {
	res, err := client.Get("https://www.hometax.go.kr/wqAction.do?actionId=ATXPPZXA001R01&screenId=UTXPPABA01")
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", errors.New(res.Status)
	}
	var data ActionATXPPZXA001R01Response
	if err = xml.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data.PkcEncSsn, nil
}

func makeLogSgnt(keyPair *certutil.KeyPair, pkcEncSsn string, signature []byte) (string, error) {
	serial := hex.EncodeToString(keyPair.Certificate.SerialNumber.Bytes())
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		return "", err
	}
	now := time.Now().In(loc)
	payload := pkcEncSsn + "$" + serial + "$" + now.Format("20060102150405") + "$" + base64.StdEncoding.EncodeToString(signature)
	return base64.StdEncoding.EncodeToString([]byte(payload)), nil
}

type LoginResult struct {
	SysCode      string
	Data         string
	Code         string // S | F
	ErrCode      string
	ErrMsg       string
	LgnRsltCd    string
	PswdErrNbcnt string
	Tin          string
	SecCardId    string
}

var regex_loginSystemCallback = regexp.MustCompile("^\\s*nts_loginSystemCallback\\('(\\w+)',\\s*(\\{.+})\\s*\\);$")
var regex_keyValue = regexp.MustCompile("'(\\w+)'\\s: (.+)")
var regex_stringValue = regexp.MustCompile("^'(.+)'$")
var regex_decodeURIComponent = regexp.MustCompile("^decodeURIComponent\\('([^']*)'\\)")

func parseLoginResult(input string) *LoginResult {
	matches := regex_loginSystemCallback.FindStringSubmatch(input)

	result := &LoginResult{
		SysCode: matches[1],
	}

	jsonContent := strings.Trim(matches[2], " {}")
	for _, line := range strings.Split(jsonContent, ",") {
		lineMatches := regex_keyValue.FindStringSubmatch(line)
		if len(lineMatches) == 3 {
			key := lineMatches[1]
			valueRaw := strings.Trim(lineMatches[2], " ")
			value, err := parseValue(valueRaw)
			if err != nil {
				log.Println(err)
				continue
			}
			switch key {
			case "code":
				result.Code = value
			case "errCode":
				result.ErrCode = value
			case "errMsg":
				result.ErrMsg = value
			case "lgnRsltCd":
				result.LgnRsltCd = value
			case "pswdErrNbcnt":
				result.PswdErrNbcnt = value
			case "tin":
				result.Tin = value
			case "secCardId":
				result.SecCardId = value
			}
		}
	}

	return result
}

func parseValue(s string) (string, error) {
	valueRaw := strings.Trim(s, " ")
	if valueRaw == "null" {
		return "", nil
	}
	matchesStr := regex_stringValue.FindStringSubmatch(valueRaw)
	if len(matchesStr) == 2 {
		return matchesStr[1], nil
	}
	matchesStr = regex_decodeURIComponent.FindStringSubmatch(valueRaw)
	if len(matchesStr) == 2 {
		return url.QueryUnescape(matchesStr[1])
	}

	return "", errors.New("unknown type: " + valueRaw)
}

func simpleGetXml(client *http.Client, url string, data string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(data)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Referer", "https://www.gov.kr/nlogin/loginByIdPwd")
	req.Header.Set("Origin", "https://www.gov.kr")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")
	req.Header.Set("Content-Type", "application/xml; charset=UTF-8")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(res.Body)
}

type PermissionLoginPpResp struct {
	XMLName xml.Name `xml:"map"`
	ID      string   `xml:"id,attr"`
	Map     struct {
		ID  string `xml:"id,attr"`
		Map []struct {
			ID                     string `xml:"id,attr"`
			TxprDscmNo             string `xml:"txprDscmNo"`
			BmanOfbDt              string `xml:"bmanOfbDt"`
			EtxivPkcYn             string `xml:"etxivPkcYn"`
			TxofOgzCd              string `xml:"txofOgzCd"`
			LgnUserClCd            string `xml:"lgnUserClCd"`
			TxprDscmNoCnfrYn       string `xml:"txprDscmNoCnfrYn"`
			HaboCl                 string `xml:"haboCl"`
			NtplBmanAthYn          string `xml:"ntplBmanAthYn"`
			SmprYn                 string `xml:"smprYn"`
			CharId                 string `xml:"charId"`
			PubcUserNo             string `xml:"pubcUserNo"`
			ThofOgzCd              string `xml:"thofOgzCd"`
			Tin                    string `xml:"tin"`
			CrtfUqno               string `xml:"crtfUqno"`
			BmanUnitEngeTrerJnngYn string `xml:"bmanUnitEngeTrerJnngYn"`
			TxprClsfCd             string `xml:"txprClsfCd"`
			UserClsfCd             string `xml:"userClsfCd"`
			DprtUserYn             string `xml:"dprtUserYn"`
			TxpAgnYn               string `xml:"txpAgnYn"`
			CnvrTin                string `xml:"cnvrTin"`
			AfaTxprYn              string `xml:"afaTxprYn"`
			SsnAltPsbYn            string `xml:"ssnAltPsbYn"`
			MpbNo                  string `xml:"mpbNo"`
			LgnClientIp            string `xml:"lgnClientIp"`
			UserId                 string `xml:"userId"`
			ChrgDutsCd             string `xml:"chrgDutsCd"`
			DataMaagClCd           string `xml:"dataMaagClCd"`
			CrpBmanAthYn           string `xml:"crpBmanAthYn"`
			LgnCertCd              string `xml:"lgnCertCd"`
			UserCertClCd           string `xml:"userCertClCd"`
			TxaaYn                 string `xml:"txaaYn"`
			WhlPmtMnpt             string `xml:"whlPmtMnpt"`
			NtplAthYn              string `xml:"ntplAthYn"`
			TxaaDprtUserAthRstnYn  string `xml:"txaaDprtUserAthRstnYn"`
			UserNm                 string `xml:"userNm"`
			SsoStatus              string `xml:"ssoStatus"`
			SystemDiv              string `xml:"systemDiv"`
			SsnChkFlag             string `xml:"ssnChkFlag"`
			SystemCode             string `xml:"systemCode"`
			ServerType             string `xml:"serverType"`
			PortalStatus           string `xml:"portalStatus"`
		} `xml:"map"`
	} `xml:"map"`
}
