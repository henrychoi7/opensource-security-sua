if err != nil {
    // 오류 처리
}

// 오류 출력 예시
{...}
if f < 0 {
    return 0, errors.New("math: square root of negative number")
}
//에러가 발생하면 에러를 출력함
if err != nil {
    fmt.Println(err)
}
{...}


// 오류가 발생한다면 정상 실행으로 돌아갈 수 있도록 하는 코드
func main () {
    start()
    fmt.Println("Returned normally from start().")
}

func start () {
    defer func () {
        if r := recover(); r != nil {
            fmt.Println("Recovered in start()")
        }
    }()
    fmt.Println("Called start()")
    part2(0)
    fmt.Println("Returned normally from part2().")
}

func part2 (i int) {
    if i > 0 {
        fmt.Println("Panicking in part2()!")
        panic(fmt.Sprintf("%v", i))
    }
    defer fmt.Println("Defer in part2()")
    fmt.Println("Executing part2()")
    part2(i + 1)
}


