func main() {
 // serveMux는 들어오는 요청을 등록된 패턴과 일치시키는 데 사용됨
 // 요청된 URL과 가장 근접하게 일치하는 핸들러를 호출함
  mux := http.NewServeMux()

  rh := http.RedirectHandler("http://yourDomain.org", 307)
  mux.Handle("/login", rh)

  log.Println("Listening...")
  http.ListenAndServe(":3000", mux)
}

