import "log"
import "net/http"

func main(){
	// http.ResponseWrite = HTTP Response에 무언가를 쓸 수 있게 함
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request){
		w.Write([]byte("This is an example server. /n"))
	})
	

	//log.Fatal() = 에러 문자열을 출력하고 프로그램을 종료하는 함수
	// http.ListenAndServeTLS = 서버에 대한 인증서, 개인 키가 포함된 파일을 서버에 제공해야 함
	log.Fatal(http.ListenAndServeTLS(":443", "yourCert.pem", "yourKey.pem", nil))
}
