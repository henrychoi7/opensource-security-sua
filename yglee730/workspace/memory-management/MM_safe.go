// go에서는 string이 null로 끝나지 않는다
type StringHeader struct {
    Data uintptr
    Len  int
}

func main() {
    strings := []string{"aaa", "bbb", "ccc", "ddd"}
    // 루프는 MAP 길이를 확인하지 않는다
    for i := 0; i < 5; i++ {
        if len(strings[i]) > 0 {
            fmt.Println(strings[i])
        }
    }
}

// 출력
aaa
bbb
ccc
ddd
panic: runtime error: index out of range
