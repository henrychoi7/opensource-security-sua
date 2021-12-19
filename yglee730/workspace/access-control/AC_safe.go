 func setToken(res http.ResponseWriter, req *http.Request) {
    // 현재 시각으로부터 30분간 토큰을 생성한다.
    // 현재 시각으로부터 30분간 쿠키를 생성한다.
    expireToken := time.Now().Add(time.Minute * 30).Unix()
    expireCookie := time.Now().Add(time.Minute * 30)

    
    claims := Claims{
        {...}
    }
    // JWT = JSON Web Token
    // NewWithClaims = 함수에 원하는 서명 메소드와 자신이 정의한 구조체를 넣어두는 곳
    // SignedString = jwt.NewWithClaims 함수로부터 값을 전달받고 토큰을 서명한다
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedToken, _ := token.SignedString([]byte("secret"))
