public static void main(String args[]) throws IOException {
// 해당 프로그램에서 실행할 프로그램을 제한하고 있지 않아 파라미터로 전달되는 모든 프로그램이
실행될 수 있다.
String cmd = args[0];
Process ps = null;
try {
ps = Runtime.getRuntime().exec(cmd);

//외부로 부터 입력 받은 값을 검증 없이 사용할 경우 안전하지 않다.
String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
Runtime.getRuntime().exec(command + date);
