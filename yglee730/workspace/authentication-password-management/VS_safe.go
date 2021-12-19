package main

import (
    "database/sql"
    "context"
    "fmt"

    "golang.org/x/crypto/bcrypt"
)

func main() {
    ctx := context.Background()
    email := []byte("john.doe@somedomain.com")
    password := []byte("47;u5:B(95m72;Xq")

    // bcrypt로 패스워드를 암호화 함
    hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
    if err != nil {
        panic(err)
    }

    // DB에 반드시 연결이 되어 있어야 함
    stmt, err := db.PrepareContext(ctx, "INSERT INTO accounts SET hash=?, email=?")
    if err != nil {
        panic(err)
    }
    result, err := stmt.ExecContext(ctx, hashedPassword, email)
    if err != nil {
        panic(err)
    }
}


ctx := context.Background()

// 검증할 인증 정보
email := []byte("john.doe@somedomain.com")
password := []byte("47;u5:B(95m72;Xq")

// 제공된 전자 메일에 해당되는 해시된 암호를 가져옴
record := db.QueryRowContext(ctx, "SELECT hash FROM accounts WHERE email = ? LIMIT 1", email)

var expectedPassword string
if err := record.Scan(&expectedPassword); err != nil {
   // 유저가 없으면

   // 로그를 남겨야 하지만 실행한다
   // 계속 진행한다
}

if bcrypt.CompareHashAndPassword(password, []byte(expectedPassword)) != nil {
   // 패스워드가 일치하지 않으면
   // 로그에 남깁니다

   // 오류에 반환되어야 "로그인 시도에 실패했습니다. 자격 증명을 확인하세요"라는 메시지가 사용자에게 뜹니다.
}
