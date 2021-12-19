package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "time"

    _ "github.com/go-sql-driver/mysql"
)

type program struct {
    base context.Context
    cancel func()
    db *sql.DB
}

func main() {
    db, err := sql.Open("mysql", "user:@/cxdb")
    if err != nil {
        log.Fatal(err)
    }
    p := &program{db: db}
    p.base, p.cancel = context.WithCancel(context.Background())

    // 프로그램 종료 요청 대기, 요청 시 기본 컨텍스트 취소
    go func() {
        osSignal := // ...
        select {
        case <-p.base.Done():
        case <-osSignal:
            p.cancel()
        }
        // 선택적으로 OS를 호출하기 전에 N 밀리초 동안 기다림.
    }()

    err =  p.doOperation()
    if err != nil {
        log.Fatal(err)
    }
}

func (p *program) doOperation() error {
    ctx, cancel := context.WithTimeout(p.base, 10 * time.Second)
    defer cancel()

    var version string
    err := p.db.QueryRowContext(ctx, "SELECT VERSION();").Scan(&version)
    if err != nil {
        return fmt.Errorf("unable to read version %v", err)
    }
    fmt.Println("Connected to:", version)
}

// XML에서 인증 정보를 저장해둔다.
<connectionDB>
  <serverDB>localhost</serverDB>
  <userDB>f00</userDB>
  <passDB>f00?bar#ItsP0ssible</passDB>
</connectionDB>

// Go파일에서 DB설정 파일을 호출함
configFile, _ := os.Open("../private/configDB.xml")

// 파일을 읽고 데이터베이스 연결을 만듬
db, _ := sql.Open(serverDB, userDB, passDB)
