// JWT를 만들고 클라이언트에 쿠키를 넣는 함수이다.
func setToken(res http.ResponseWriter, req *http.Request) {
  ...
}

// 세션 식별자를 생성하는 데 사용되는 알고리즘이 세션을 무작위로 생성한다.
...
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signedToken, _ := token.SignedString([]byte("secret")) //our secret
...

// 쿠키의 파라미터들이다.
cookie := http.Cookie{
    Name: "Auth",
    Value: signedToken,
    Expires: expireCookie,
    HttpOnly: true,
    Path: "/",
    Domain: "127.0.0.1",
    Secure: true
}

http.SetCookie(res, &cookie)

// 중간자 공격을 방지하기 위해 HTTPS를 사용하는 것도 방법이다
err := http.ListenAndServeTLS(":443", "cert/cert.pem", "cert/key.pem", nil)
if err != nil {
  log.Fatal("ListenAndServe: ", err)
}


// 로그아웃하면 쿠키가 클라이언트에서 삭제된다
...
cookie, err := req.Cookie("Auth")
if err != nil {
  res.Header().Set("Content-Type", "text/html")
  fmt.Fprint(res, "Unauthorized - Please login <br>")
  fmt.Fprintf(res, "<a href=\"login\"> Login </a>")
  return
}
...
