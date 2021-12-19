package main

import "fmt"
import "io"
import "crypto/md5"
import "crypto/sha256"
import "golang.org/x/crypto/blake2s"

func main () {
        h_md5 := md5.New()
        h_sha := sha256.New()
        h_blake2s, _ := blake2s.New256(nil)
	
	// md5로 암호화
        io.WriteString(h_md5, "Welcome to Go Language Secure Coding Practices")

	// sha256으로 암호화
        io.WriteString(h_sha, "Welcome to Go Language Secure Coding Practices")

	// blake2로 암호화
	// black2 : MD5, SHA-1, SHA-2, SHA-3보다 빠른 암호화 해시 함수, SHA-3만큼 안전
        io.WriteString(h_blake2s, "Welcome to Go Language Secure Coding Practices")
        fmt.Printf("MD5        : %x\n", h_md5.Sum(nil))
        fmt.Printf("SHA256     : %x\n", h_sha.Sum(nil))
        fmt.Printf("Blake2s-256: %x\n", h_blake2s.Sum(nil))
}

// 암호화
encrypted_data := F(data, key)

// 복호화
data := F⁻¹(encrypted_data, key)
