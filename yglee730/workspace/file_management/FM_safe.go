{...}
// 버퍼에 512 바이트만큼 쓸 수 있다
buff := make([]byte, 512)

_, err = file.Read(buff)
{...}

// 파일 타입을 저장한다
filetype := http.DetectContentType(buff)


// 지정한 파일 타입만 허용한다
{...}
switch filetype {
case "image/jpeg", "image/jpg":
  fmt.Println(filetype)
case "image/gif":
  fmt.Println(filetype)
case "image/png":
  fmt.Println(filetype)
default:
  fmt.Println("unknown file type uploaded")
}
{...}
