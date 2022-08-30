//외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String gubun = request.getParameter("gubun");
......
String sql = "SELECT * FROM board WHERE b_gubun = '" + gubun + "'";
Connection con = db.getConnection();
Statement stmt = con.createStatement();
//외부로부터 입력받은 값이 검증 또는 처리 없이 쿼리로 수행되어 안전하지 않다.
ResultSet rs = stmt.executeQuery(sql);
