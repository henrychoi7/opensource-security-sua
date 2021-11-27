String gubun = request.getParameter("gubun");
......
//1. 사용자에 의해 외부로부터 입력받은 값은 안전하지 않을 수 있으므로, PreparedStatement
사용을 위해 ?문자로 바인딩 변수를 사용한다.
String sql = "SELECT * FROM board WHERE b_gubun = ?";
Connection con = db.getConnection();
//2. PreparedStatement 사용한다.
PreparedStatement pstmt = con.prepareStatement(sql);
//3.PreparedStatement 객체를 상수 스트링으로 생성하고, 파라미터 부분을 setString등의 메소드로
설정하여 안전하다.
pstmt.setString(1, gubun);
ResultSet rs = pstmt.executeQuery();
