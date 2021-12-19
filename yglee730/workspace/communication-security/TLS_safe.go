
type Certificates struct {
    CertFile    string
    KeyFile     string
}

func main() {
    httpsServer := &http.Server{
        Addr: ":8080",
    }

    var certs []Certificates
    certs = append(certs, Certificates{
        CertFile: "../etc/yourSite.pem", //본인 사이트의 인증서 키 
        KeyFile:  "../etc/yourSite.key",  // 본인 사이트의 개인키
    })

    config := &tls.Config{}
    var err error
	
    config.Certificates = make([]tls.Certificate, len(certs))
    for i, v := range certs {
	// LoadX509KeyPair = 파일에서 공개/개인 키를 읽으면서 분석함.
        config.Certificates[i], err = tls.LoadX509KeyPair(v.CertFile, v.KeyFile)
    }

    conn, err := net.Listen("tcp", ":8080")

    tlsListener := tls.NewListener(conn, config)
    httpsServer.Serve(tlsListener)
    fmt.Println("Listening on port 8080...")
}
