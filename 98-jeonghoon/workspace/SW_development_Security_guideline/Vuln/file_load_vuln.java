MultipartRequest multi
= new MultipartRequest(request,savePath,sizeLimit,"euc-kr",new
DefaultFileRenamePolicy());
......
//업로드 되는 파일명을 검증없이 사용하고 있어 안전하지 않다.
String fileName = multi.getFilesystemName("filename");
......
sql = " INSERT INTO
board(email,r_num,w_date,pwd,content,re_step,re_num,filename) "
+ " values ( ?, 0, sysdate(), ?, ?, ?, ?, ? ) ";
preparedStatement pstmt = con.prepareStatement(sql);
pstmt.setString(1, stemail);
pstmt.setString(2, stpwd);
pstmt.setString(3, stcontent);
pstmt.setString(4, stre_step);
pstmt.setString(5, stre_num);
pstmt.setString(6, fileName);
pstmt.executeUpdate();
Thumbnail.create(savePath+"/"+fileName, savePath+"/"+"s_"+fileName, 150);
