// FileServer : 서버에 저장된 파일들을 보여줌 (디렉토리 인덱싱 취약점 가능성)
http.ListenAndServe(":8080", http.FileServer(http.Dir("/tmp/static")))
