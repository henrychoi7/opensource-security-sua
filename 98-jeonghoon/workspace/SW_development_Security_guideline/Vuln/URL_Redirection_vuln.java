String id = (String)session.getValue("id");
String bn = request.getParameter("gubun");
//외부로부터 입력받은 URL이 검증없이 다른 사이트로 이동이 가능하여 안전하지 않다.
String rd = request.getParameter("redirect");
if (id.length() > 0) {
String sql = "select level from customer where customer_id = ? ";
conn = db.getConnection();
pstmt = conn.prepareStatement(sql);
pstmt.setString(1, id);
rs = pstmt.executeQuery();
rs.next();
if ("0".equals(rs.getString(1)) && "01AD".equals(bn)) {
response.sendRedirect(rd);
return;
}
