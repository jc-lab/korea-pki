# korea-pki

공인인증 (AnySign) 을 위한 라이브러리 입니다.

```bash
go get github.com/jc-lab/korea-pki
```

라이선스 구매 설명: https://jsty.tistory.com/351

# License

See [LICENSE.txt](./LICENSE.txt)

## 상업용 라이선스

korea-pki를 사용하여 비공개 소스 상업용 프로젝트 및 애플리케이션을 개발하려면 Commercial 라이센스가 적합한 라이센스입니다. 이 옵션을 사용하면 소스 코드가 독점적으로 유지됩니다. korea-pki 상용 라이센스를 구입하려면 joseph@jc-lab.net 으로 문의하세요.

If you want to use korea-pki to develop commercial projects, and applications, the Commercial license is the appropriate license. With this option, your source code is kept proprietary. To purchase a korea-pki commercial license, please contact joseph@jc-lab.net

상업용 라이선스의 특징은 아래와 같습니다.
- 소스 코드 독점적 유지: 라이선스가 부여 된 소프트웨어를 사용하는 소프트웨어의 소스코드를 독점적으로 유지할 수 있습니다.
- 재배포: 라이선스가 부여 된 소프트웨어를 재배포하거나 재판매할 수 없습니다.
- 보증: 이 제품에는 반대되는 법률에도 불구하고 명시적이든 묵시적이든 어떠한 보증도 제공되지 않습니다.

## 오픈소스 라이선스

SSPL-1.0 과 호환되는 라이선스에 따라 오픈 소스 애플리케이션을 만드는 경우 SSPL-1.0의 조건에 따라 korea-pki 를 사용할 수 있습니다.

If you are creating an open source application under a license compatible with the SSPL-1.0, you may use korea-pki under the terms of the SSPL-1.0.

# 특징

## WebBrowser 사용 안함

selenium 이나 Chrome Browser 를 사용하지 않고 오직 Network 만을 이용하기 때문에 빠릅니다.

## AnySign4 지원

AnySign4 을 사용하는 사이트들에 로그인을 구현할 수 있습니다.

예제:

- 정부24 공동인증서(파일) 로그인 : [examples/govkr/main.go](./examples/govkr/main.go)

# Examples

- 정부24 공동인증서(파일) 로그인 : [examples/govkr/main.go](./examples/govkr/main.go)
- 국세청 홈택스(HomeTax) 공동인증서(파일) 로그인 : [examples/hometax/main.go](./examples/hometax/main.go) : 
