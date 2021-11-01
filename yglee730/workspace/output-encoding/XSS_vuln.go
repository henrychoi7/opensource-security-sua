package main

import "net/http"

// 기본 인터페이스를 제공하는 패키지
import "io"

func handler (w http.ResponseWriter, r *http.Request) {
    // URL 쿼리에서 param1이라는 이름을 가진 파라미터의 값을 받고, 페이지에 씀 
    io.WriteString(w, r.URL.Query().Get("param1"))
}

func main () {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8070", nil)
}
