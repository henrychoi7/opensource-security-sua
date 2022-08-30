// 입력화면이 요청되었을 때, 임의의 토큰을 생성한 후 세션에 저장한다.
session.setAttribute("SESSION_CSRF_TOKEN", UUID.randomUUID().toString());
// 입력화면에 임의의 토큰을 HIDDEN 필드항목의 값으로 설정해 서버로 전달되도록 한다.
<input type="hidden" name="param_csrf_token" value="${SESSION_CSRF_TOKEN}"/>
// 요청 파라미터와 세션에 저장된 토큰을 비교해서 일치하는 경우에만 요청을 처리한다.
String pToken = request.getParameter("param_csrf_token");
String sToken = (String)session.getAttribute("SESSION_CSRF_TOKEN");
if (pToken != null && pToken.equals(sToken) {
// 일치하는 토큰이 존재하는 경우 -> 정상 처리
......
} else {
// 토큰이 없거나 값이 일치하지 않는 경우 -> 오류 메시지 출력
......

