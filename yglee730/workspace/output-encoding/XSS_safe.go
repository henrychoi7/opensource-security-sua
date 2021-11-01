package main

import "net/http"

// HTML 출력을 자동으로 보호해주는 패키지
import "text/template"

func handler(w http.ResponseWriter, r *http.Request) {
	// URL Query에서 param1의 값을 받아옴
        param1 := r.URL.Query().Get("param1")
	
	// HTML 템플릿의 문맥을 자동으로 이스케이프 해줌
        tmpl := template.New("hello")
        tmpl, _ = tmpl.Parse(`{{define "T"}}{{.}}{{end}}`)
        tmpl.ExecuteTemplate(w, "T", param1)
}

func main() {
        http.HandleFunc("/", handler)
        http.ListenAndServe(":8070", nil)
}
