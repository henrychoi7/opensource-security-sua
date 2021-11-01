package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go" //JWT = JSON Web Token
)

type Key int

const MyKey Key = 0

// 저장할 데이터의 JWT 스키마
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Homepage(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/html")
	fmt.Fprint(res, "Unauthorized - Please login <br>")
	fmt.Fprintf(res, "<a href=\"login\"> Login </a> <br>")
	fmt.Fprintf(res, "<a href=\"profile?page=page2\"> URL Parameters page 2 - Protected </a> <br>")
	fmt.Fprintf(res, "<a href=\"profile\"> Profile - Protected </a> <br>")
}

// JWT 생성 후 클라이언트에 쿠키를 넣는다
func setToken(res http.ResponseWriter, req *http.Request) {
	// 민감하지 않은 애플리케이션의 경우 30분 후 만료
	expireToken := time.Now().Add(time.Minute * 30).Unix()
	expireCookie := time.Now().Add(time.Minute * 30)

	//토큰 클레임
	// payload 부분에는 토큰에 담을 정보가 들어있는데, 여기에 담는 정보의 한 조각을 클레임이라고 함
	claims := Claims{
		"TestUser",
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "localhost:9000",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("secret"))

	//쿠키 파라미터 세팅
	//30분 후 만료
	//HTTP 전용
	//경로
	//도메인
	cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true, Path: "/", Domain: "127.0.0.1", Secure: true}
	http.SetCookie(res, &cookie)
	http.Redirect(res, req, "/profile", http.StatusTemporaryRedirect)
}

// 개인 페이지를 보호하는 미들웨어
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

// 클라이언트에 유효한 토큰이 있는 경우에만 볼 수 있음
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

// 쿠키 제거
func logout(res http.ResponseWriter, req *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
	http.SetCookie(res, &deleteCookie)
}

func main() {
	http.HandleFunc("/", Homepage)
	http.HandleFunc("/login", setToken)
	http.HandleFunc("/profile", validate(protectedProfile))
	http.HandleFunc("/logout", validate(logout))
	err := http.ListenAndServeTLS(":443", "cert/cert.pem", "cert/key.pem", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	//http.ListenAndServe(":9000", nil)
}
