//외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String fileName = request.getParameter("P");
BufferedInputStream bis = null;
BufferedOutputStream bos = null;
FileInputStream fis = null;
try {
response.setHeader("Content-Disposition", "attachment;filename="+fileName+";");
...
//외부로부터 입력받은 값이 검증 또는 처리 없이 파일처리에 수행되었다.
fis = new FileInputStream("C:/datas/" + fileName);
bis = new BufferedInputStream(fis);
bos = new BufferedOutputStream(response.getOutputStream());
