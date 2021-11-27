//이동 할 수 있는 URL범위를 제한하여 피싱 사이트등으로 이동 못하도록 한다.
String allowedUrl[] = { "/main.do", "/login.jsp", "list.do" };
......
String rd = request.getParameter("redirect");
try {
rd = allowedUrl[Integer.parseInt(rd)];
} catch(NumberFormatException e) {
return "잘못된 접근입니다.";
} catch(ArrayIndexOutOfBoundsException e) {
return "잘못된 입력입니다.";
}
if (id.length() > 0) {
......
if ("0".equals(rs.getString(1)) && "01AD".equals(bn)) {
response.sendRedirect(rd);
return;
}
