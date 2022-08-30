# SQL injection은 인용문자 다음에 SQL을 주입하는 입력 제공형태를 취하는데 이것을 피하는것이다.
# String sql = "SELECT * FROM User WHERE userId = ?";
PreparedStatement stmt = con.prepareStatement(sql);
stmt.setString(1, userId);
ResultSet rs = prepStmt.executeQuery();
