// DecodeString = 16진수 문자열을 나타내는 바이트로 반환
// 반환 값 = change this password to a secret
secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
if err != nil {
    panic(err)
}

var secretKey [32]byte
// secretKey = "change this password to a secret"
copy(secretKey[:], secretKeyBytes)

var nonce [24]byte
if _, err := rand.Read(nonce[:]); err != nil {
    panic(err)
}

// secretbox = 작은 메시지를 암호화하고 인증함
// encrypted = 암호화된 "hello world"
encrypted := secretbox.Seal(nonce[:], []byte("hello world"), &nonce, &secretKey)

var decryptNonce [24]byte
copy(decryptNonce[:], encrypted[:24])
// 복호화 할 때는 암호화 할 때 사용한 것과 동일한 nonce와 키를 사용해야 함
decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretKey)
if !ok {
    panic("decryption error")
}

fmt.Println(string(decrypted))
