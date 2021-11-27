String fileName = request.getParameter("P");
BufferedInputStream bis = null;
BufferedOutputStream bos = null;
FileInputStream fis = null;
try {
response.setHeader("Content-Disposition", "attachment;filename="+fileName+";");
...
// 외부 입력받은 값을 경로순회 문자열(./￦)을 제거하고 사용해야한다.
filename = filename.replaceAll("￦￦.", "").replaceAll("/", "").replaceAll("￦￦￦￦", "");
fis = new FileInputStream("C:/datas/" + fileName);
bis = new BufferedInputStream(fis);
bos = new BufferedOutputStream(response.getOutputStream());
int read;

while((read = bis.read(buffer, 0, 1024)) != -1) {
bos.write(buffer,0,read);
}
}
