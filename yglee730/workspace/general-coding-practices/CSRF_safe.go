package main

import (
    "net/http"

    "github.com/gorilla/csrf"
    "github.com/gorilla/mux"
)

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/signup", ShowSignupForm)

    // 유효한 토큰이 없는 POST 요청은 HTTP 403 Forbidden을 반환함. 
    r.HandleFunc("/signup/post", SubmitSignupForm)

    // 라우터를 래핑하여 미들웨어를 추가함.
    http.ListenAndServe(":8000",
        csrf.Protect([]byte("32-byte-long-auth-key"))(r))
}

func ShowSignupForm(w http.ResponseWriter, r *http.Request) {
    // signup_form.tmpl은 {{ .csrfField }} 태그가 필요함.
    // CSRF 토큰을 csrf.TemplateField에 넣어야 하기 때문
    t.ExecuteTemplate(w, "signup_form.tmpl", map[string]interface{}{
        csrf.TemplateTag: csrf.TemplateField(r),
    })
    // csrf.Token(r)에서 직접 토큰을 검색하여 요청 헤더에 설정할 수도 있음
    // w.Header.Set("X-CSRF-Token",token)

    // JSON을 클라이언트나 Front-End 자바스크립트 프레임워크에 보내는 경우에 유용함
}

func SubmitSignupForm(w http.ResponseWriter, r *http.Request) {
}
