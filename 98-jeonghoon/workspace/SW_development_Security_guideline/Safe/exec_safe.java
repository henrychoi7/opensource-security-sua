public static void main(String args[]) throws IOException {
// 해당 어플리케이션에서 실행할 수 있는 프로그램을 노트패드와 계산기로 제한하고 있다.
List<String> allowedCommands = new ArrayList<String>(); “
allowedCommands.add("notepad"); allowedCommands.add("calc");
String cmd = args[0];
if (!allowedCommands.contains(cmd)) {
System.err.println("허용되지 않은 명령어입니다.");
return;
}
Process ps = null; try {
ps = Runtime.getRuntime().exec(cmd);

String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
//외부로부터 입력 받은 값을 필터링을 통해 우회문자를 제거하여 사용한다.
date = date.replaceAll("|","");
date = date.replaceAll(";","");
date = date.replaceAll("&","");
date = date.replaceAll(":","");
date = date.replaceAll(">",""); Runtime.getRuntime().exec(command + date);

