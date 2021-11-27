
# Secure Coding Guidelines for Java
위 문서는 다음 문서를 참고하여 작성되었습니다.

[소프트웨어 개발보안 가이드 - KISA](https://www.kisa.or.kr/uploadfile/201702/201702140920275581.pdf)

[Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html)

## 입력데이터 검증 및 표현
프로그램 입력값에 대한 검증 누락 또는 부적절한 검증, 데이터의 잘못된 형식지정, 일관되지 않은
언어셋 사용 등으로 인해 발생되는 보안약점으로 SQL 삽입, 크로스사이트 스크립트(XSS) 등의
공격을 유발할 수 있다.

### SQL injection
```html
데이터베이스(DB)와 연동된 웹 응용프로그램에서 입력된 데이터에 대한 유효성 검증을 하지 않을
경우, 공격자가 입력 폼 및 URL 입력란에 SQL 문을 삽입하여 DB로부터 정보를 열람하거나 조작할
수 있는 보안약점을 말한다.
```

####취약코드
```java
//외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String gubun = request.getParameter("gubun");
......
String sql = "SELECT * FROM board WHERE b_gubun = '" + gubun + "'";
Connection con = db.getConnection();
Statement stmt = con.createStatement();
//외부로부터 입력받은 값이 검증 또는 처리 없이 쿼리로 수행되어 안전하지 않다.
ResultSet rs = stmt.executeQuery(sql);
```
gubun의 값으로 a' or 'a' = 'a 를 입력하면
조건절이 b_gubun = 'a' or 'a' = 'a' 로 바뀌어 쿼리의 구조가 변경되어 board 테이블의 모든 내용이
조회된다.

####안전한 코드
```java
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
```
파라미터(Parameter)를 받는 PreparedStatement
객체를 상수 스트링으로 생성하고, 파라미터 부분을 setString, setParameter등의 메소드로 설정
하여, 외부의 입력이 쿼리문의 구조를 바꾸는 것을 방지해야 한다.

### 경로 조작 및 자원 삽입
```
검증되지 않은 외부 입력값을 통해 파일 및 서버 등 시스템 자원에 대한 접근 혹은 식별을 허용할
경우, 입력값 조작을 통해 시스템이 보호하는 자원에 임의로 접근할 수 있는 보안약점이다.
```

####취약코드
```java
//외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String fileName = request.getParameter("P");
BufferedInputStream bis = null;
BufferedOutputStream bos = null;
FileInputStream fis = null;
try {
response.setHeader("Content-Disposition", "attachment;filename="+fileName+";");
...
//외부로부터 입력받은 값이 검증 또는 처리 없이 파일처리에 수행되었다.
fis = new FileInputStream("C:/datas/" + fileName);
bis = new BufferedInputStream(fis);
bos = new BufferedOutputStream(response.getOutputStream());
```
외부 입력값(P)이 버퍼로 내용을 옮길 파일의 경로설정에 사용되고 있다. 만일 공격자에 의해 P의
값으로 ../../../rootFile.txt와 같은 값을 전달하면 의도하지 않았던 파일의 내용이 버퍼에 쓰여
시스템에 악영향을 준다.

####안전한 코드
```java
String fileName = request.getParameter("P");
BufferedInputStream bis = null;
BufferedOutputStream bos = null;
FileInputStream fis = null;
try {
response.setHeader("Content-Disposition", "attachment;filename="+fileName+";");
...
// 외부 입력받은 값을 경로순회 문자열(./￦)을 제거하고 사용해야한다.
filename = filename.replaceAll("￦￦.", "").replaceAll("/", "").replaceAll("￦￦￦￦", "");
fis = new FileInputStream("C:/datas/" + fileName);
bis = new BufferedInputStream(fis);
bos = new BufferedOutputStream(response.getOutputStream());
int read;
while((read = bis.read(buffer, 0, 1024)) != -1) {
    bos.write(buffer,0,read);}
}
```
외부 입력값에 대하여 상대경로를 설정할 수 없도록 경로순회 문자열( / ￦ & .. 등 )을 제거하고 파일
의 경로설정에 사용한다.

### XSS(Cross-Site Scripting)
```
웹 페이지에 악의적인 스크립트를 포함시켜 사용자 측에서 실행되게 유도할 수 있다. 예를 들어,
검증되지 않은 외부 입력이 동적 웹페이지 생성에 사용될 경우, 전송된 동적 웹페이지를 열람하는
접속자의 권한으로 부적절한 스크립트가 수행되어 정보유출 등의 공격을 유발할 수 있다.
```

####취약코드
```java
<% String keyword = request.getParameter("keyword"); %>
//외부 입력값에 대하여 검증 없이 화면에 출력될 경우 공격스크립트가 포함된 URL을 생성 할 수 있어
        안전하지 않다.(Reflected XSS)
        검색어 : <%=keyword%>
//게시판 등의 입력form을 통해 외부값이 DB에 저장되고, 이를 검증 없이 화면에 출 력될 경우
        공격스크립트가 실행되어 안전하지 않다.(Stored XSS)
        검색결과 : ${m.content}
<script type="text/javascript">
//외부 입력값에 대하여 검증 없이 브라우저에서 실행되는 경우 서버를 거치지 않는 공격스크립트가
        포함된 URL을 생성 할 수 있어 안전하지 않다. (DOM 기반 XSS)
        document.write("keyword:" + <%=keyword%>);
</script>
```

####안전한 코드
```java
<% String keyword = request.getParameter("keyword"); %>
// 방법1. 입력값에 대하여 스크립트 공격가능성이 있는 문자열을 치환한다.
        keyword = keyword.replaceAll("&", "&amp;");
        keyword = keyword.replaceAll("<", "&lt;");
        keyword = keyword.replaceAll(">", "&gt;");
        162
        전자정부 SW 개발·운영자를 위한
        안전한 코드의 예 JAVA
        keyword = keyword.replaceAll("￦"", "&quot;");
        keyword = keyword.replaceAll("'", "&#x27;");
        keyword = keyword.replaceAll("/"", "&#x2F;");
        keyword = keyword.replaceAll("(", "&#x28;");
        keyword = keyword.replaceAll(")", "&#x29;");
        검색어 : <%=keyword%>
//방법2. JSP에서 출력값에 JSTL c:out 을 사용하여 처리한다.
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
        검색결과 : <c:out value="${m.content}"/>
<script type="text/javascript">
//방법3. 잘 만들어진 외부 라이브러리를 활용(NAVER Lucy-XSS-Filter, OWASP ESAPI, OWASP
        Java-Encoder-Project)
        document.write("keyword:" +
<%=Encoder.encodeForJS(Encoder.encodeForHTML(keyword))%>);
</script>
```
외부 입력값 파라미터나 게시판등의 form에 의해 서버의 처리 결과를 사용자 화면에 출력하는 경우,
입력값에 대해서 문자열 치환 함수를 이용하여 스크립트 문자열을 제거하거나, JSTL을 이용하여
출력하거나, 잘 만들어진 외부 XSS 방지 라이브러리를 활용하는 것이 안전하다.

### 운영체제 명령어 삽입
```
적절한 검증절차를 거치지 않은 사용자 입력값이 운영체제 명령어의 일부 또는 전부로 구성되어 실행
되는 경우, 의도하지 않은 시스템 명령어가 실행되어 부적절하게 권한이 변경되거나 시스템 동작 및
운영에 악영향을 미칠 수 있다.
```

####취약코드 - 1
```java
public static void main(String args[]) throws IOException {
// 해당 프로그램에서 실행할 프로그램을 제한하고 있지 않아 파라미터로 전달되는 모든 프로그램이
        실행될 수 있다.
        String cmd = args[0];
        Process ps = null;
        try {
        ps = Runtime.getRuntime().exec(cmd);
        ...
```
Runtime.getRuntime().exec()명령어를 통해 프로그램을 실행하며, 외부에서 전달
되는 인자값은 명령어의 생성에 사용된다. 그러나 해당 프로그램에서 실행할 프로그램을 제한하지
않고 있기 때문에 외부의 공격자는 가능한 모든 프로그램을 실행시킬 수 있다.
####취약코드 - 2
```java
//외부로 부터 입력 받은 값을 검증 없이 사용할 경우 안전하지 않다.
String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
Runtime.getRuntime().exec(command + date);
```
외부입력값을 검증하지 않고 그대로 명령어로 실행하기 때문에 공격자의 입력에 따라
의도하지 않은 명령어가 실행될 수 있다.

####안전한 코드 - 1
```java
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
```
미리 정의된 파라미터의 배열을 만들어 놓고, 외부의 입력에 따라 적절한 파라
미터를 선택하도록 하여, 외부의 부적절한 입력이 명령어로 사용될 가능성을 배제하여야 한다.

####안전한 코드 - 2
```java
String date = request.getParameter("date");
String command = new String("cmd.exe /c backuplog.bat");
//외부로부터 입력 받은 값을 필터링을 통해 우회문자를 제거하여 사용한다.
date = date.replaceAll("|","");
date = date.replaceAll(";","");
date = date.replaceAll("&","");
date = date.replaceAll(":","");
date = date.replaceAll(">",""); Runtime.getRuntime().exec(command + date);

```
운영체제 명령어 실행 시에는 아래와 같이 외부에서 들어오는 값에 의하여 멀티라인을지원하는 특수
문자(| ; & :)나 파일 리다이렉트 특수문자(> >>)등을 제거하여 원하지 않은 운영체제 명령어가 실행
될 수 없도록 필터링을 수행한다.

### 위험한 형식 파일 업로드

```
서버 측에서 실행될 수 있는 스크립트 파일(asp, jsp, php 파일 등)이 업로드가능하고, 이 파일을
공격자가 웹을 통해 직접 실행시킬 수 있는 경우, 시스템 내부명령어를 실행하거나 외부와 연결하여
시스템을 제어할 수 있는 보안약점이다.
```

####취약코드 - 1
```java
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
```
업로드할 파일에 대한 유효성을 검사하지 않으면, 위험한 유형의 파일을 공격자가 업로드하거나 전송
할 수 있다

####안전한 코드 - 1
```java
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
```

업로드 파일의 확장자를 검사하여 허용되지 않은 확장자인 경우 업로드를 제한하고 있다.

### 신뢰되지 않는 URL 주소로 자동접속 연결

```
사용자로부터 입력되는 값을 외부사이트의 주소로 사용하여 자동으로 연결하는 서버 프로그램은
피싱(Phishing) 공격에 노출되는 취약점을 가질 수 있다.
```

####취약코드 - 1
```java
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
```
경우 공격자는 아래와 같은 링크를 통해 희생자가 피싱 사이트 등으로 접근하도록 할 수 있다.
(예시 링크)<a href="http://bank.example.com/redirect?url=http://attacker.example.net">Click</a>

####안전한 코드 - 1
```java
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
```

### 신뢰되지 않는 URL 주소로 자동접속 연결

```
사용자로부터 입력되는 값을 외부사이트의 주소로 사용하여 자동으로 연결하는 서버 프로그램은
피싱(Phishing) 공격에 노출되는 취약점을 가질 수 있다.
```

####취약코드 - 1
```java
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
```
경우 공격자는 아래와 같은 링크를 통해 희생자가 피싱 사이트 등으로 접근하도록 할 수 있다.
(예시 링크)<a href="http://bank.example.com/redirect?url=http://attacker.example.net">Click</a>

####안전한 코드 - 1
```java
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
```
외부로 연결할 URL과 도메인들은 화이트 리스트를 작성한 후, 그 중에서
선택하도록 함으로써 안전하지 않은 사이트로의 접근을 차단할 수 있다.

### XQuery 삽입

```
XQuery를 사용하여 XML 데이터에 대한 동적 쿼리를 생성 시 사용되는 외부 입력값에 대해 적절한
검증절차가 존재하지 않으면 공격자가 쿼리문의 구조를 임의로 변경할 수 있게 된다. 이로 인해 허가
되지 않은 데이터를 조회하거나 인증절차를 우회할 수 있다.
```

####취약코드
```java
1. // 외부 입력 값을 검증하지 않고 XQuery 표현식에 사용한다.
2. String name = props.getProperty("name");
3. .......
4. // 외부 입력 값에 의해 쿼리 구조가 변경 되어 안전하지 않다.
5. String es = "doc('users.xml')/userlist/user[uname='"+name+"']";
6. XQPreparedExpression expr = conn.prepareExpression(es);
7. XQResultSequence result = expr.executeQuery();
```
만일 something' or '1'='1 을 name의 값으로 전달하면 다음과 같은
쿼리문을 수행할 수 있으며, 이를 통해 파일 내의 모든 값을 출력할 수 있게 된다.
doc('users.xml')/userlist/user[uname='something' or '1‘='1’]

####안전한 코드
```java
1. // blingString 함수로 쿼리 구조가 변경되는 것을 방지한다.
2. String name = props.getProperty("name");
3. ....... 
4. String es = "doc('users.xml')/userlist/user[uname='$xname']";
5. XQPreparedExpression expr = conn.prepareExpression(es);
6. expr.bindString(new QName("xname"), name, null);
7. XQResultSequence result = expr.executeQuery();
```
외부 입력값을 받고 해당 값 기반의 XQuery상의 쿼리 구조를 변경시키지 않는
bindString 함수를 이용함으로써 외부 입력값을 통해 쿼리 구조가 변경될 수 없도록 한다.

### XPath 삽입

```
외부 입력값을 적절한 검사과정 없이 XPath 쿼리문 생성을 위한 문자열로 사용하면, 공격자는 프로
그래머가 의도하지 않았던 문자열을 전달하여 쿼리문의 의미를 왜곡시키거나 그 구조를 변경하고
임의의 쿼리를 실행하여 인가되지 않은 데이터를 열람할 수 있다.
```

####취약코드
```java
// 프로퍼티로부터 외부 입력값 name과 password를 읽어와 각각 nm, pw변수에 저장
String nm = props.getProperty("name");
String pw = props.getProperty("password");
......
XPathFactory factory = XPathFactory.newInstance();
XPath xpath = factory.newXPath();
......
// 검증되지 않은 입력값 외부 입력값 nm, pw 를 사용하여 안전하지 않은 질의문이 작성되어 expr
변수에 저장된다.
XPathExpression expr = xpath.compile("//users/user[login/text()='"+nm+"' and
password/text()='"+pw+"']/home_dir/text()");
만일 something' or '1'='1 을 name의 값으로 전달하면 다음과 같은
쿼리문을 수행할 수 있으며, 이를 통해 파일 내의 모든 값을 출력할 수 있게 된다.
doc('users.xml')/userlist/user[uname='something' or '1‘='1’]
// 안전하지 않은 질의문이 담긴 expr을 평가하여 결과를 result에 저장한다.
Object result = expr.evaluate(doc, XPathConstants.NODESET);
// result의 결과를 NodeList 타입으로 변환하여 nodes 저장한다.
// NodeList nodes = (NodeList) result;
        for (int i=0; i<nodes.getLength(); i++) {
        String value = nodes.item(i).getNodeValue();
        if (value.indexOf(">") < 0) {
// 공격자가 이름과 패스워드를 확인할 수 있다. System.out.println(value);
        }
}
```
nm과 pw에 대한 입력값 검증을 수행하지 않으므로 nm의 값으로 "tester", pw의
값으로 "x' or 'x'='x"을 전달하면 아래와 같은 질의문이 생성되어 인증과정 을 거치지 않고 로그인할
수 있다.
"//users/user[login/text()='tester' and password/text()='x' or //'x'='x']/home_dir/text()"

####안전한 코드
```java
[ login.xq 파일 ]
declare variable $loginID as xs:string external; declare variable $password as xs:string
external;
//users/user[@loginID=$loginID and @password=$password]
// XQuery를 이용한 XPath Injection 방지
String nm = props.getProperty("name");
String pw = props.getProperty("password");
Document doc = new Builder().build("users.xml");
// 파라미터화된 쿼리가 담겨있는 login.xq를 읽어와서 파라미터화된 쿼리를 생성한다.
XQuery xquery = new XQueryFactory().createXQuery(new File("login.xq"));
Map vars = new HashMap();
// 검증되지 않은 외부값인 nm, pw를 파라미터화된 쿼리의 파라미터로 설정한다.
외부 입력값을 받고 해당 값 기반의 XQuery상의 쿼리 구조를 변경시키지 않는
bindString 함수를 이용함으로써 외부 입력값을 통해 쿼리 구조가 변경될 수 없도록 한다.
vars.put("loginID", nm);
vars.put("password", pw);
// 파라미터화된 쿼리를 실행하므로 외부값을 검증없이 사용하여도 안전하다.
Nodes results = xquery.execute(doc, null, vars).toNodes();
for (int i=0; i<results.size(); i++) {
        System.out.println(results.get(i).toXML());
}
```
예제는 XQuery를 사용하여 미리 쿼리 골격을 생성함으로써 외부입력으로 인해 쿼리 구조가
바뀌는 것을 막을 수 있다

### LDAP 삽입

```
공격자가 외부 입력을 통해서 의도하지 않은 LDAP(Lightweight Directory Access Protocol)
명령어를 수행할 수 있다. 
```

####취약코드
```java
private void searchRecord(String userSN, String userPassword) throws
NamingException {
Hashtable<String, String> env = new Hashtable<String, String>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
try {
DirContext dctx = new InitialDirContext(env);
SearchControls sc = new SearchControls();
String[] attributeFilter = { "cn", "mail" };
        sc.setReturningAttributes(attributeFilter);
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String base = "dc=example,dc=com";
//userSN과 userPassword 값에 LDAP필터를 조작할 수 있는 공격 문자열에 대한 검증이 없어 안전하지 않다.
        String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
        NamingEnumeration<?> results = dctx.search(base, filter, sc);
        while (results.hasMore()) {
        SearchResult sr = (SearchResult) results.next();
        Attributes attrs = sr.getAttributes();
        Attribute attr = attrs.get("cn");
        .....
        }
        dctx.close();
        } catch (NamingException e) { … }
        }
```
userSN과 userPassword 변수의 값으로 *을 전달할 경우 필터 문자열은 "(&(sn=S*)(userPassword=*))“ 가
되어 항상 참이 되며 이는 의도하지 않은 동작을 유발시킬 수 있다.

####안전한 코드
```java
private void searchRecord(String userSN, String userPassword) throws
NamingException {
Hashtable<String, String> env = new Hashtable<String, String>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
try {
DirContext dctx = new InitialDirContext(env);
SearchControls sc = new SearchControls();
String[] attributeFilter = {"cn", "mail" };
sc.setReturningAttributes(attributeFilter);
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";
// userSN과 userPassword 값에서 LDAP 필터를 조작할 수 있는 문자열을 제거하고 사용
if (!userSN.matches("[￦￦w￦￦s]*") || !userPassword.matches("[￦￦w]*")) {
throw new IllegalArgumentException("Invalid input");
}
String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
NamingEnumeration<?> results = dctx.search(base, filter, sc);
while (results.hasMore()) {
SearchResult sr = (SearchResult) results.next();
Attributes attrs = sr.getAttributes();
Attribute attr = attrs.get("cn");
......
}
dctx.close();
} catch (NamingException e) { … }
}
```
검색을 위한 필터 문자열로 사용되는 외부의 입력에서 위험한 문자열을 제거하여 위험성을 부분적
으로 감소시킬 수 있다.

### 크로스사이트 요청 위조

```
특정 웹사이트에 대해서 사용자가 인지하지 못한 상황에서 사용자의 의도와는 무관하게 공격자가
의도한 행위(수정, 삭제, 등록 등)를 요청하게 하는 공격을 말한다. 웹 응용프로그램이 사용자로부터
받은 요청에 대해서 사용자가 의도한 대로 작성되고 전송된 것인지 확인하지 않는 경우 발생 가능
하고 특히 해당 사용자가 관리자인 경우 사용자 권한관리, 게시물삭제, 사용자 등록 등 관리자 권한
으로만 수행 가능한 기능을 공격자의 의도대로 실행시킬 수 있게 된다.
```

####취약코드
```java
// 어떤 형태의 요청이던지 기본적으로 CSRF 취약점을 가질 수 있다.
```
클라이언트로부터의 요청(request)에 대해서 정상적인 요청 여부인지를 검증하지 않고 처리하는
경우, 크로스사이트 요청 위조 공격에 쉽게 노출될 수 있다

####안전한 코드
```java
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
}
```
정상 요청 여부를 판단하기 위해 토큰을 이용한다. 사용자가 입력(신청) 페이지를 요청하면 임의의
토큰을 생성한 후 세션에 저장하고, 입력(신청) 페이지에 생성한 토큰을 HIDDEN 필드 항목의 값으로 설정한다. 입력(신청)을 처리하는 페이지에서는 입력(신청) 페이지에서 요청 파라미터로 전달 된 HIDDEN 필드의 토큰 값과 세션에 저장된 토큰 값을 비교하여 일치하는 경우에만 정상 요청으로 
판단하여 입력(신청)이 처리될 수 있도록 한다.

### HTTP 응답분할

```
HTTP 요청에 들어 있는 파라미터(Parameter)가 HTTP 응답헤더에 포함되어 사용자에게 다시 전달될 때,
입력값에 CR(Carriage Return)이나 LF(Line Feed)와 같은 개행문자가 존 재하면 HTTP
응답이 2개 이상으로 분리될 수 있다. 이 경우 공격자는 개행문자를 이용하여 첫 번째 응답을 종료
시키고, 두 번째 응답에 악의적인 코드를 주입하여 XSS 및 캐시 훼손(Cache Poisoning) 공격 등을
수행할 수 있다.
```

####취약코드
```java
//외부로부터 입력받은 값을 검증 없이 사용할 경우 안전하지 않다.
String lastLogin = request.getParameter("last_login");
if (lastLogin == null || "".equals(lastLogin)) {
return;
}
// 쿠키는 Set-Cookie 응답헤더로 전달되므로 개행문자열 포함 여부 검증이 필요
Cookie c = new Cookie("LASTLOGIN", lastLogin);
c.setMaxAge(1000);
c.setSecure(true);
response.addCookie(c);
response.setContentType("text/html");
클라이언트로부터의 요청(request)에 대해서 정상적인 요청 여부인지를 검증하지 않고 처리하는
경우, 크로스사이트 요청 위조 공격에 쉽게 노출될 수 있다
```
외부 입력값을 사용하여 반환되는 쿠키의 값을 설정하고 있다. 그런데, 공격자가 Wiley Hacker ￦r￦nHTTP/1.1 200 OK￦r￦n를 lastLogin의 값으로 설정할 경우, 응답이 분리되어 전달되며 
분리된 응답 본문의 내용을 공격자가 마음대로 수정할 수 있다.

####안전한 코드
```java
String lastLogin = request.getParameter("last_login");
if (lastLogin == null || "".equals(lastLogin)) {
return;
}
// 외부 입력값에서 개행문자(￦r￦n)를 제거한 후 쿠키의 값으로 설정
lastLogin = lastLogin.replaceAll("[￦￦r￦￦n]", "");
Cookie c = new Cookie("LASTLOGIN", lastLogin);
c.setMaxAge(1000);
c.setSecure(true);
response.addCookie(c);
```
외부에서 입력되는 값에 대하여 null 여부를 체크하고, 응답이 여러 개로 나눠지는 것을 방지하기
위해 개행문자를 제거하고 응답헤더의 값으로 사용한다

### 정수형 오버플로우

```
정수형 오버플로우는 정수형 크기는 고정되어 있는데 저장 할 수 있는 범위를 넘어서, 크 기보다 큰
값을 저장하려 할 때 실제 저장되는 값이 의도치 않게 아주 작은 수이거나 음수가 되어 프로그램이
예기치 않게 동작 될수 있다. 특히 반복문 제어, 메모리 할당, 메모리 복사 등을 위한 조건으로 사용자
가 제공하는 입력값을 사용하고 그 과정에서 정수형 오버플로우가 발생하는 경우 보안상 문제를 유발
할 수 있다.
```

####취약코드
```java
String msg_str = "";
String tmp = request.getParameter("slf_msg_param_num");
tmp = StringUtil.isNullTrim(tmp);
if (tmp.equals("0")) {
msg_str = PropertyUtil.getValue(msg_id);
} else {
// 외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하지 않고 사용
int param_ct = Integer.parseInt(tmp);
String[] strArr = new String[param_ct];
```
외부의 입력(slf_msg_param_num)을 이용하여 동적으로 계산한 값을 배열의 크기
(size)를 결정하는데 사용하고 있다. 만일 외부 입력으로부터 계산된 값(param_ct)이 오버 플로우에
의해 음수값이 되면, 배열의 크기가 음수가 되어 시스템에 문제가 발생할 수 있다.

####안전한 코드
```java
String msg_str = "";
String tmp = request.getParameter("slf_msg_param_num");
tmp = StringUtil.isNullTrim(tmp);
if (tmp.equals("0")) {
msg_str = PropertyUtil.getValue(msg_id);
} else {
// 외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하고 사용
try {
int param_ct = Integer.parseInt(tmp);
if (param_ct < 0) {
throw new Exception();
}
String[] strArr = new String[param_ct];
} catch(Exception e) {
msg_str = "잘못된 입력(접근) 입니다.";
}
```
동적 메모리 할당을 위해 외부 입력값을 배열의 크기로 사용하는 경우 그 값이 음수가 아닌지 검사
하는 작업이 필요하다.

### 보안기능 결정에 사용되는 부적절한 입력값

```
응용프로그램이 외부 입력값에 대한 신뢰를 전제로 보호메커니즘을 사용하는 경우 공격자가 입력값
을 조작할 수 있다면 보호메커니즘을 우회할 수 있게 된다. 인증이나 인가와 같은 보안결정이 이런 
입력값(쿠키, 환경변수, 히든필드 등)에 기반해 수행 되는 경우 공격자는 이런 입력값을 조작하여 
응용프로그램의 보안을 우회할 수 있으므로 충분한 암호화, 무결성 체크를 수행하고 이와 같은 메커니즘이 
없는 경우엔 외부사용자에 의한 입력값을 신뢰해서는 안된다.
```

####취약코드
```java
<input type="hidden" name="price" value="1000"/>
<br/>품목 : HDTV
<br/>수량 : <input type="hidden" name="quantity" />개
<br/><input type="submit" value="구입" />
......
try {
// 서버가 보유하고 있는 가격(단가) 정보를 사용자 화면에서 받아서 처리
    price = request.getParameter("price");
    quantity = request.getParameter("quantity");
    total = Integer.parseInt(quantity) * Float.parseFloat(price);
} catch (Exception e) {
.....
```
구입품목의 가격을 사용자 웹브라우저에서 처리하고 있어 이 값이 사용자에 의해 변경되는 경우 가격
(단가)정보가 의도하지 않은 값으로 할당될 수 있다.

####안전한 코드
```java
<input type="hidden" name="price" value="1000"/>
<br/>품목 : HDTV
<br/>수량 : <input type="hidden" name="quantity" />개
<br/><input type="submit" value="구입" />
......
try {
item = request.getParameter(“item”);
// 가격이 아니라 item 항목을 가져와서 서버가 보유하고 있는 가격 정보를
// 이용하여 전체 가격을 계산
price = productService.getPrice(item);
quantity = request.getParameter("quantity");
total = Integer.parseInt(quantity) * price;
} catch (Exception e) {
......
}
......
```
사용자 권한, 인증 여부 등 보안결정에 사용하는 값은 사용자 입력값을 사용하지 않고 서버 내부의
값을 활용한다. 또한 사용자 입력에 의존해야하는 값을 제외하고는 반드시 서버가 보유하고 있는
정보를 이용하여 처리한다.

### Format String Bug

```
외부로부터 입력된 값을 검증하지 않고 입·출력 함수의 포맷 문자열로 그대로 사용하는 경우 발생할
수 있는 보안약점이다. 공격자는 포맷 문자열을 이용하여 취약한 프로세스를 공격하거나 메모리 내용
을 읽거나 쓸 수 있다. 그 결과, 공격자는 취약한 프로세스의 권한을 취득하여 임의의 코드를 실행할
수 있다
```

####안전한 코드
```java
// 외부 입력값이 포맷 문자열 출력에 사용되지 않도록 수정
import java.util.Calendar
:
public static void main(String[] args) {
        Calendar validDate = Calendar.getInstance();
        validDate.set(2014, Calendar.OCTOBER, 14);
        System.out.printf("%s did not match! HINT: It was issued on %2$terd of some
        month", args[0], validate);
        }

```
사용자로부터 입력 받은 문자열을 포맷 문자열에 직접 포함시키지 않고, %s 포맷 문자열을 사용함
으로써 정보유출을 방지한다.

## 보안기능

### 적절한 인증 없는 중요기능 허용

```
적절한 인증과정이 없이 중요정보(계좌이체 정보, 개인정보 등)를 열람(또는 변경)할 때 발생하는 보안약점이다.
```

####취약코드
```java
@RequestMapping(value = "/modify.do", method = RequestMethod.POST)
public ModelAndView memberModifyProcess(@ModelAttribute("MemberModel")
MemberModel memberModel, BindingResult result, HttpServletRequest request,
HttpSession session) {
ModelAndView mav = new ModelAndView();
//1. 로그인한 사용자를 불러온다.
String userId = (String) session.getAttribute("userId");
구입품목의 가격을 사용자 웹브라우저에서 처리하고 있어 이 값이 사용자에 의해 변경되는 경우 가격
(단가)정보가 의도하지 않은 값으로 할당될 수 있다.
String passwd = request.getParameter("oldUserPw");
...
//2. 실제 수정하는 사용자와 일치 여부를 확인하지 않고, 회원정보를 수정하여 안전하지 않다.
if (service.modifyMember(memberModel)) {
mav.setViewName("redirect:/board/list.do");
session.setAttribute("userName", memberModel.getUserName());
return mav;
} else {
mav.addObject("errCode", 2);
mav.setViewName("/board/member_modify");
return mav;
}
}
```
회원정보 수정 시 수정을 요청한 사용자와 로그인한 사용자의 일치 여부를 확인하지 않고 처리하고 있다.

####안전한 코드
```java
@RequestMapping(value = "/modify.do", method = RequestMethod.POST)
public ModelAndView memberModifyProcess(@ModelAttribute("MemberModel")
MemberModel memberModel, BindingResult result, HttpServletRequest request,
        HttpSession session) {
        ModelAndView mav = new ModelAndView();
//1. 로그인한 사용자를 불러온다.
        String userId = (String) session.getAttribute("userId");
        String passwd = request.getParameter("oldUserPw");
//2. 회원정보를 실제 수정하는 사용자와 로그인 사용자와 동일한지 확인한다.
        String requestUser = memberModel.getUserId();
        if (userId != null && requestUser != null && !userId.equals(requestUser)) {
        mav.addObject("errCode", 1);
        mav.addObject("member", memberModel);
        mav.setViewName("/board/member_modify");
        return mav;
        }
        ...
//3. 동일한 경우에만 회원정보를 수정해야 안전하다.
        if (service.modifyMember(memberModel)) {
        ...

        }
```
로그인한 사용자와 요청한 사용자의 일치 여부를 확인한 후 회원정보를 수정하도록 한다.

### 부적절한 인가

```
프로그램이 모든 가능한 실행경로에 대해서 접근제어를 검사하지 않거나 불완전하게 검사하는 경우,
공격자는 접근 가능한 실행경로를 통해 정보를 유출할 수 있다.
```

####취약코드
```java
private BoardDao boardDao;
        String action = request.getParameter("action");
        String contentId = request.getParameter("contentId");
//요청을 하는 사용자의 delete 작원 권한 확인 없이 수행하고 있어 안전하지 않다.
        if (action != null && action.equals("delete")) {
        boardDao.delete(contentId);
        }
```
코드는 사용자 입력값에 따라 삭제작업을 수행하고 있으며, 사용자의 권한 확인을 위한 별도
의 통제가 적용되지 않고 있다.

####안전한 코드
```java
private BoardDao boardDao;
        String action = request.getParameter("action");
        String contentId = request.getParameter("contentId");
// 세션에 저장된 사용자 정보를 얻어온다.
        User user= (User)session.getAttribute("user");
// 사용자정보에서 해당 사용자가 delete작업의 권한이 있는지 확인한 뒤 삭제 작업을 수행한다.
        if (action != null && action.equals("delete") &&
        checkAccessControlList(user,action)) {
        boardDao.delete(contenId);
        }
        }
```
세션에 저장된 사용자 정보를 통해 해당 사용자가 삭제작업을 수행할 권한이 있는지
확인한 뒤 권한이 있는 경우에만 수행하도록 해야 한다.

### 부적절한 인가

```
프로그램이 모든 가능한 실행경로에 대해서 접근제어를 검사하지 않거나 불완전하게 검사하는 경우,
공격자는 접근 가능한 실행경로를 통해 정보를 유출할 수 있다.
```

####취약코드
```java
private BoardDao boardDao;
        String action = request.getParameter("action");
        String contentId = request.getParameter("contentId");
//요청을 하는 사용자의 delete 작원 권한 확인 없이 수행하고 있어 안전하지 않다.
        if (action != null && action.equals("delete")) {
        boardDao.delete(contentId);
        }
```
코드는 사용자 입력값에 따라 삭제작업을 수행하고 있으며, 사용자의 권한 확인을 위한 별도
의 통제가 적용되지 않고 있다.

####안전한 코드
```java
private BoardDao boardDao;
        String action = request.getParameter("action");
        String contentId = request.getParameter("contentId");
// 세션에 저장된 사용자 정보를 얻어온다.
        User user= (User)session.getAttribute("user");
// 사용자정보에서 해당 사용자가 delete작업의 권한이 있는지 확인한 뒤 삭제 작업을 수행한다.
        if (action != null && action.equals("delete") &&
        checkAccessControlList(user,action)) {
        boardDao.delete(contenId);
        }
        }
```
세션에 저장된 사용자 정보를 통해 해당 사용자가 삭제작업을 수행할 권한이 있는지
확인한 뒤 권한이 있는 경우에만 수행하도록 해야 한다.

### 중요한 자원에 대한 잘못된 권한 설정

```
SW가 중요한 보안관련 자원에 대하여 읽기 또는 수정하기 권한을 의도하지 않게 허가할 경우, 권한
을 갖지 않은 사용자가 해당 자원을 사용하게 된다.
```

####취약코드
```java
File file = new File("/home/setup/system.ini");
//모든 사용자에게 실행 권한을 허용하여 안전하지 않다.
        file.setExecutable(true, false);
        //모든 사용자에게 읽기 권한을 허용하여 안전하지 않다.
        file.setReadable(true, false);
//모든 사용자에게 쓰기 권한을 허용하여 안전하지 않다.
        file.setWritable(true, false);
```
>setExecutable(p1, p2) : 첫 번째 파라미터의 true/false 값에 따라 실행가능 여부를 결정한다.
두 번째 파라미터가 true 일 경우 소유자만 실행 권한을 가지며, false 일 경우 모든 사용자가
실행 권한을 가진다.
>>setReadable(p1, p2) : 첫 번째 파라미터의 true/false 값에 따라 읽기가능 여부를 결정한다.
두 번째 파라미터가 true 일 경우 소유자만 읽기권한을 가지며, false 일 경우 모든 사용자가
읽기 권한을 가진다.
>>> setWritable(p1, p2) : 첫 번째 파라미터의 true/false 값에 따라 쓰기가능 여부를 결정한다. 두
번째 파라미터가 true 일 경우 소유자만 쓰기권한을 가지며, false 일 경우 모든 사용자가 쓰기
권한을 가진다.


####안전한 코드
```java
File file = new File("/home/setup/system.ini");
//소유자에게 실행 권한을 금지하였다.
        file.setExecutable(false);
//소유자에게 읽기 권한을 허용하였다.
        file.setReadable(true);
//소유자에게 쓰기 권한을 금지하였다.
        file.setWritable(false);

```
파일에 대해서는 최소권한을 할당해야 한다. 즉 해당 파일의 소유자에게만 읽기 권한을 부여한다
> setExecutable(p1) : 파라미터의 true/false 값에 따라 소유자의 실행권한 여부를 결정한다.
>> setReadable(p1) : 파라미터의 true/false 값에 따라 소유자의 읽기권한 여부를 결정한다.
>>> setWritable(p1) : 파라미터의 true/false 값에 따라 소유자의 쓰기권한 여부를 결정한다.

### 취약한 암호화 알고리즘 사용

```
SW 개발자들은 환경설정 파일에 저장된 패스워드를 보호하기 위하여 간단한 인코딩 함수를 이용
하여 패스워드를 감추는 방법을 사용하기도 한다. 그렇지만 base64와 같은 지나치게 간단한 인코딩
함수로는 패스워드를 제대로 보호할 수 없다.
정보보호 측면에서 취약하거나 위험한 암호화 알고리즘을 사용해서는 안 된다. 표준화되지 않은
암호화 알고리즘을 사용하는 것은 공격자가 알고리즘을 분석하여 무력화시킬 수 있는 가능성을 높일
수도 있다.
```

####취약코드
```java
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
public class CryptoUtils {
    public byte[] encrypt(byte[] msg, Key k) {
        byte[] rslt = null;
        try {
//키 길이가 짧아 취약함 암호와 알고리즘인 DES를 사용하여 안전하지 않다.
            Cipher c = Cipher.getInstance("DES");
            c.init(Cipher.ENCRYPT_MODE, k);
            rslt = c.update(msg);
        }
```
취약한 DES 알고리즘으로 암호화하고 있다.


####안전한 코드
```java
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
public class CryptoUtils {
    public byte[] encrypt(byte[] msg, Key k) {
        byte[] rslt = null;
        try {
//키 길이가 길어 강력한 알고리즘인 AES를 사용하여 안전하다.
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, k);
            rslt = c.update(msg);
        }

```
안전하다고 알려진 AES 알고리즘 등을 적용해야 한다.

### 중요정보 평문저장

```
많은 응용프로그램은 메모리나 디스크에서 중요한 데이터(개인정보, 인증정보, 금융정보)를 처리한다.
이러한 중요 데이터가 제대로 보호되지 않을 경우, 보안이나 데이터의 무결성을 잃을 수 있다. 특히
프로그램이 개인정보, 인증정보 등의 사용자 중요정보 및 시스템 중요정보를 처리하는 과정에서 이를
평문으로 저장할 경우 공격자에게 민감한 정보가 노출될 수 있다.
```

####취약코드
```java
String id = request.getParameter("id");
// 외부값에 의해 패스워드 정보를 얻고 있다.
        String pwd = request.getParameter("pwd");
        ......
        String sql = " insert into customer(id, pwd, name, ssn, zipcode, addr)"
        + " values (?, ?, ?, ?, ?, ?)";
        PreparedStatement stmt = con.prepareStatement(sql);
        stmt.setString(1, id);
        stmt.setString(2, pwd);
        ......
// 입력받은 패스워드가 평문으로 DB에 저장되어 안전하지 않다.
        stmt.executeUpdate();
```
인증을 통과한 사용자의 패스워드 정보가 평문으로 DB에 저장된다.


####안전한 코드
```java
String id = request.getParameter("id");
// 외부값에 의해 패스워드 정보를 얻고 있다.
        String pwd = request.getParameter("pwd");
// 패스워드를 솔트값을 포함하여 SHA-256 해시로 변경하여 안전하게 저장한다.
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(salt);
        byte[] hashInBytes = md.digest(pwd.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
        sb.append(String.format("%02x", b));
        }
        pwd = sb.toString();
        ......
        String sql = " insert into customer(id, pwd, name, ssn, zipcode, addr)"
        + " values (?, ?, ?, ?, ?, ?)";
        PreparedStatement stmt = con.prepareStatement(sql);
        stmt.setString(1, id);
        stmt.setString(2, pwd);
        ......
        stmt.executeUpdate();
```
패스워드 등 중요 데이터를 해쉬값으로 변환하여 저장하고 있다.