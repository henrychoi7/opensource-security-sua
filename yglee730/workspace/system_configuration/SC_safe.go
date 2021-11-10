// Proto는 무시되고 HTTP/1.1을 사용하여 요청됨
req, _ := http.NewRequest("POST", url, buffer)
req.Proto = "HTTP/1.0"

// 디렉토리 목록을 비활성화 하는 방법
type justFilesFilesystem struct {
    fs http.FileSystem
}

// 요청된 경로와 파일이 표시될 수 있는지의 여부를 확인하는 함수
func (fs justFilesFilesystem) Open(name string) (http.File, error) {
    f, err := fs.fs.Open(name)
    if err != nil {
        return nil, err
    }
    return neuteredReaddirFile{f}, nil
}

// tmp/static/ 경로만 표시하도록 허용함
fs := justFilesFilesystem{http.Dir("tmp/static/")}
http.ListenAndServe(":8080", http.StripPrefix("/tmp/static", http.FileServer(fs)))

// X-Request-With 헤더를 Go vulnerable Framework 1.2로 변경함
w.Header().Set("X-Request-With", "Go Vulnerable Framework 1.2")

// POST, GET 메소드만 허용함
w.Header().Set("Access-Control-Allow-Methods", "POST, GET")

// Allow에 나온 경로만 허용하고 나머지는 전부 허용하지 않음
User-agent: *
Allow: /sitemap.xml
Allow: /index
Allow: /contact
Allow: /aboutus
Disallow: /
