func main(){
	
	http.ListenAndServe(":8070", nil)
	
	// Origin = URL에서 스키마, 호스트, 포트를 합친 것
	// Header에서 Origin을 가져오고 호스트랑 같지 않으면 에러
	if r.Header.Get("Origin") != "http://"+r.Host{
		http.Error(w, "Origin not allowed", 403)
			return
	}else{
		websocket.Handler(EchoHandler).ServeHTTP(w, r)
	}
}
