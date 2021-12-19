// 성공적인 보안 이벤트와 실패한 보안 이벤트를 모두 다뤄야 함
func main() {
    var buf bytes.Buffer
    var RoleLevel int

    logger := log.New(&buf, "logger: ", log.Lshortfile)

    fmt.Println("Please enter your user level.")
    fmt.Scanf("%d", &RoleLevel) //<--- example

    switch RoleLevel {
    case 1:
        // 로그인 성공
        logger.Printf("Login successful.")
        fmt.Print(&buf)
    case 2:
        // 실패한 로그인
        logger.Printf("Login unsuccessful - Insufficient access level.")
        fmt.Print(&buf)
     default:
        // 지정되지 않은 오류
        logger.Print("Login error.")
        fmt.Print(&buf)
    }
}


// 암호화 해시 함수를 추가하여 로그 변조가 발생하지 않도록 함
{...}

// 체크섬 파일에서 알려진 로그 체크섬을 가져옴
logChecksum, err := ioutil.ReadFile("log/checksum")
str := string(logChecksum) // 내용을 문자열로 반환

// 현재 로그의 SHA256 해시 계산
b, err := ComputeSHA256("log/log")
if err != nil {
  fmt.Printf("Err: %v", err)
} else {
  hash := hex.EncodeToString(b)
  // 계산된 해시를 저장된 해시와 비교함

  if str == hash {
    // 확인 체크섬이 일치
    fmt.Println("Log integrity OK.")
  } else {
    // 파일 무결성이 손상됨
    fmt.Println("File Tampering detected.")
  }
}
{...}
