MultipartRequest multi
= new MultipartRequest(request,savePath,sizeLimit,"euc-kr",new
DefaultFileRenamePolicy());
......
String fileName = multi.getFilesystemName("filename");
if (fileName != null) {
//1.업로드 파일의 마지막 “.” 문자열의 기준으로 실제 확장자 여부를 확인하고, 대소문자 구별을
해야한다.
String fileExt =
FileName.substring(fileName.lastIndexOf(".")+1).toLowerCase();
//2.되도록 화이트 리스트 방식으로 허용되는 확장자로 업로드를 제한해야 안전하다.
if (!"gif".equals(fileExt) && !"jpg".equals(fileExt) && !"png".equals(fileExt))
{
alertMessage("업로드 불가능한 파일입니다.");
return;
}
}
......
sql = " INSERT INTO
board(email,r_num,w_date,pwd,content,re_step,re_num,filename) "
+ " values ( ?, 0, sysdate(), ?, ?, ?, ?, ? ) ";
PreparedStatement pstmt = con.prepareStatement(sql);
......
Thumbnail.create(savePath+"/"+fileName, savePath+"/"+"s_"+fileName, 150);
