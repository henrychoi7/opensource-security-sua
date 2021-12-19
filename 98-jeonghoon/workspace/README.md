
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드 - 1
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
#### 취약코드 - 2
```java
//외부로 부터 입력 받은 값을 검증 없이 사용할 경우 안전하지 않다.
String date = request.getParameter("date");
        String command = new String("cmd.exe /c backuplog.bat");
        Runtime.getRuntime().exec(command + date);
```
외부입력값을 검증하지 않고 그대로 명령어로 실행하기 때문에 공격자의 입력에 따라
의도하지 않은 명령어가 실행될 수 있다.

#### 안전한 코드 - 1
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

#### 안전한 코드 - 2
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

#### 취약코드 - 1
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

#### 안전한 코드 - 1
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

#### 취약코드 - 1
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

#### 안전한 코드 - 1
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

#### 취약코드 - 1
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

#### 안전한 코드 - 1
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
```java
// 어떤 형태의 요청이던지 기본적으로 CSRF 취약점을 가질 수 있다.
```
클라이언트로부터의 요청(request)에 대해서 정상적인 요청 여부인지를 검증하지 않고 처리하는
경우, 크로스사이트 요청 위조 공격에 쉽게 노출될 수 있다

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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

#### 안전한 코드
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

#### 취약코드
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


#### 안전한 코드
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

#### 취약코드
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


#### 안전한 코드
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

#### 취약코드
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


#### 안전한 코드
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

### 중요정보 평문전송


```
사용자 또는 시스템의 중요정보가 포함된 데이터를 평문으로 송·수신할 경우, 통신채널 스니핑을
통해 인가되지 않은 사용자에게 민감한 데이터가 노출될 수 있는 보안약점이다.

```

#### 취약코드
```java
try {
        Socket s = new Socket("taranis", 4444);
        PrintWriter o = new PrintWriter(s.getOutputStream(), true);
//패스워드를 평문으로 전송하여 안전하지 않다.
        String password = getPassword();
        o.write(password);
        } catch (FileNotFoundException e) {
```
패스워드를 암호화하지 않고 네트워크를 통해 전송하고 있다. 이 경우 패킷 스니핑을
통하여 패스워드가 노출될 수 있다.



#### 안전한 코드
```java
// 패스워드를 암호화 하여 전송
try {
        Socket s = new Socket("taranis", 4444);
        PrintStream o = new PrintStream(s.getOutputStream(), true);
//패스워드를 강력한 AES암호화 알고리즘을 통해 전송하여 사용한다.
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String password = getPassword();
        byte[] encPassword = c.update(password.getBytes());
        o.write(encPassword, 0, encPassword.length);
        } catch (FileNotFoundException e) {
        ……

```
패스워드를 네트워크를 통해 서버로 전송하기 전에 AES 등의 안전한 암호알고리즘으로
암호화한 안전한 프로그램이다.

### 솔트 없이 일방향 해쉬함수 사용



```
패스워드를 저장 시 일방향 해쉬함수의 성질을 이용하여 패스워드의 해쉬값을 저장한다. 만약 패스
워드를 솔트(Salt)없이 해쉬하여 저장한다면, 공격자는 레인보우 테이블과 같이 해시값을 미리 계산
하여 패스워드를 찾을 수 있게 된다

```

#### 취약코드
```java
public String getPasswordHash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
//해쉬에 솔트를 적용하지 않아 안전하지 않다.
        md.update(password.getBytes());
        byte byteData[] = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i=0; i<byteData.length i++) {
        String hex=Integer.toHexString(0xff & byteData[i]);
        if (hex.length() == 1) {
        hexString.append('0');
        }
        hexString.append(hex);
        }
        return hexString.toString();
        }
```
패스워드 저장 시 솔트 없이 패스워드에 대한 해쉬값을 얻는 과정을 보여준다

#### 안전한 코드
```java
// 패스워드를 암호화 하여 전송
public String getPasswordHash(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());
//해시사용시에는 원문을 찾을 수 없도록 솔트를 사용하여야한다.
        md.update(salt);
        byte byteData[] = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i=0; i<byteData.length i++) {
        String hex=Integer.toHexString(0xff & byteData[i]);
        if (hex.length() == 1) {
        hexString.append('0');
        }
        hexString.append(hex);
        }
        return hexString.toString()
        }

```
패스워드만을 해쉬함수의 입력으로 사용하기에 레인보우 테이블을 이용한 사전 공격이 가능하며,
이를 방지하기 위해 패스워드와 솔트를 함께 해쉬함수에 적용하여 사용한다.
## 시간 및 상태
동시 또는 거의 동시 수행을 지원하는 병렬 시스템이나 하나 이상의 프로세스가 동작되는 환경에서
시간 및 상태를 부적절하게 관리하여 발생할 수 있는 보안약점이다.

###  경쟁조건: 검사시점과 사용시점(TOCTOU)

```
하나의 자원에 대하여 동시에 검사시점과 사용시점이 달라 생기는 보안약점으로 인해
동기화 오류뿐만 아니라 교착상태 등과 같은 문제점이 발생할 수 있다.


```

#### 취약코드
```java
class FileMgmtThread extends Thread {
    private String manageType = "";
    public FileMgmtThread (String type) {
        manageType = type;
    }
//멀티쓰레드 환경에서 공유자원에 여러프로세스가 사용하여 동시에 접근할 가능성이 있어 안전하지
    않다.
    public void run() {
        try {
            if (manageType.equals("READ")) {
                File f = new File("Test_367.txt");
                if (f.exists()) {
                    BufferedReader br
                            = new BufferedReader(new FileReader(f));
                    br.close();
                }
            } else if (manageType.equals("DELETE")) {
                File f = new File("Test_367.txt");
                if (f.exists()) {
                    f.delete();
                } else { … }
            }
        } catch (IOException e) { … }
    }
}

```
파일을 대한 읽기와 삭제가 두 개의 스레드에 동작하게 되므로 이미 삭제된 파일을
읽으려고 하는 레이스컨디션이 발생할 수 있다.

#### 안전한 코드
```java
class FileMgmtThread extends Thread {
    private static final String SYNC = "SYNC";
    private String manageType = "";
    public FileMgmtThread (String type) {
        manageType = type;
    }
    public void run() {
//멀티쓰레드 환경에서 synchronized를 사용하여 동시에 접근할 수 없도록 사용해야한다.
        synchronized(SYNC) {
            try {
                if (manageType.equals("READ")) {
                    File f = new File("Test_367.txt");
                    if (f.exists()) {
                        BufferedReader br
                                = new BufferedReader(new FileReader(f));
                        br.close();
                    }

```
동기화 구문인 synchronized를 사용하여 공유자원 (Test_367.txt)에 대한
안전한 읽기/쓰기를 수행할 수 있도록 한다.

## 에러처리
에러를 처리하지 않거나, 불충분하게 처리하여 에러 정보에 중요정보(시스템 내부정보 등)가 포함될
때, 발생할 수 있는 취약점으로 에러를 부적절하게 처리하여 발생하는 보안약점이다.

###  오류 메시지를 통한 정보노출

```
응용프로그램이 실행환경, 사용자 등 관련 데이터에 대한 민감한 정보를 포함하는 오류 메시지를
생성하여 외부에 제공하는 경우, 공격자의 악성 행위를 도울 수 있다. 예외발생 시 예외이름이나 스택
트레이스를 출력하는 경우, 프로그램 내부구조를 쉽게 파악할 수 있기 때문이다.
```

#### 취약코드
```java
try {
        rd = new BufferedReader(new FileReader(new File(filename)));
        } catch(IOException e) {
// 에러 메시지를 통해 스택 정보가 노출됨
        e.printStackTrace();
        }

```
오류메시지에 예외 이름이나 오류추적 정보를 출력하여 프로그램 내부 정보가 유출되는
경우이다

#### 안전한 코드
```java
try {
        rd = new BufferedReader(new FileReader(new File(filename)));
        } catch(IOException e) {
// 에러 코드와 정보를 별도로 정의하고 최소 정보만 로깅
        logger.error("ERROR-01: 파일 열기 에러");
        }

```
예외 이름이나 오류추적 정보를 출력하지 않도록 한다.

### 오류 상황 대응 부재


```
오류가 발생할 수 있는 부분을 확인하였으나, 이러한 오류에 대하여 예외 처리를 하지 않을 경우,
공격자는 오류 상황을 악용하여 개발자가 의도하지 않은 방향으로 프로그램이 동작하도록 할 수 있다.

```

#### 취약코드
```java
protected Element createContent(WebSession s) {
        ……
        try {
        username = s.getParser().getRawParameter(USERNAME);
        password = s.getParser().getRawParameter(PASSWORD);
        if (!"webgoat".equals(username) || !password.equals("webgoat")) {
        s.setMessage("Invalid username and password entered.");
        return (makeLogin(s));
        }
        } catch (NullPointerException e) {
//요청 파라미터에 PASSWORD가 존재하지 않을 경우 Null Pointer Exception이 발생하고 해당
        오류에 대한 대응이 존재하지 않아 인증이 된 것으로 처리
        }
```
try 블록에서 발생하는 오류를 포착(catch)하고 있지만, 그 오류에 대해서 아무 조치를
하고 있지 않음을 보여준다. 아무 조치가 없으므로 프로그램이 계속 실행되기 때문에 프로그램에서
어떤 일이 일어났는지 전혀 알 수 없게 된다.


#### 안전한 코드
```java
protected Element createContent(WebSession s) {
        ……
        try {
        username = s.getParser().getRawParameter(USERNAME);
        password = s.getParser().getRawParameter(PASSWORD);
        if (!"webgoat".equals(username) || !password.equals("webgoat")) {
        s.setMessage("Invalid username and password entered.");
        return (makeLogin(s));
        }
        } catch (NullPointerException e) {
//예외 사항에 대해 적절한 조치를 수행하여야 한다.
        s.setMessage(e.getMessage());
        return (makeLogin(s));
        }

```
예외를 포착(catch)한 후, 각각의 예외 사항(Exception)에 대하여 적절하게 처리해야 한다

### 부적절한 예외 처리


```
프로그램 수행 중에 함수의 결과값에 대한 적절한 처리 또는 예외 상황에 대한 조건을 적절하게 검사
하지 않을 경우, 예기치 않은 문제를 야기할 수 있다.

```

#### 취약코드
```java
try {
        ...
        reader = new BufferedReader(new InputStreamReader(url.openStream()));
        String line = reader.readLine();
        SimpleDateFormat format = new SimpleDateFormat("MM/DD/YY");
        Date date = format.parse(line);
//예외처리를 세분화 할 수 있음에도 광범위하게 사용하여 예기치 않은 문제가 발생 할 수 있다.
        } catch (Exception e) {
        System.err.println("Exception : " + e.getMessage());
        }
```
try 블록에서 다양한 예외가 발생할 수 있음에도 불구하고 예외를 세분화하지 않고 광범
위한 예외 클래스인 Exception을 사용하여 예외를 처리하고 있다.


#### 안전한 코드
```java
try {
        ...
        reader = new BufferedReader(new InputStreamReader(url.openStream()));
        String line = reader.readLine();
        SimpleDateFormat format = new SimpleDateFormat("MM/DD/YY");
        Date date = format.parse(line);
// 발생할 수 있는 오류의 종류와 순서에 맞춰서 예외 처리 한다.
        } catch (MalformedURLException e) {
        System.err.println("MalformedURLException : " + e.getMessage());
        } catch (IOException e) {
        System.err.println("IOException : " + e.getMessage());
        } catch (ParseException e) {
        System.err.println("ParseException : " + e.getMessage());
        }


```
발생 가능한 예외를 세분화하고 발생 가능한 순서에 따라 예외를 처리하고 있다

## 코드오류
타입 변환 오류, 자원(메모리 등)의 부적절한 반환 등과 같이 개발자가 범할 수 있는 코딩오류로 인해
유발되는 보안약점이다

### Null Pointer 역참조

```
널 포인터(Null Pointer) 역참조는 '일반적으로 그 객체가 널(Null)이 될 수 없다'라고 하는 가정을
위반했을 때 발생한다. 공격자가 의도적으로 널 포인터 역참조를 발생시키는 경우, 그 결과 발생하는
예외 상황을 이용하여 추후의 공격을 계획하는 데 사용될 수 있다.

```

#### 취약코드
```java
public static int cardinality (Object obj, final Collection col) {
        int count = 0;
        if (col == null) {
        return count;
        }
        Iterator it = col.iterator();
        while (it.hasNext()) {
        Object elt = it.next();
        //obj가 null이고 elt가 null이 아닐 경우, Null.equals 가 되어 널(Null) 포인터 역참조가 발생한다.
        if ((null == obj && null == elt) || obj.equals(elt)) {
        count++;
        }
        }
        return count;
        }

```
obj가 null이고, elt가 null이 아닌 경우 널(Null) 포인터 역참조가 발생한다

#### 안전한 코드
```java
public static int cardinality (Object obj, final Collection col) {
        int count = 0;
        if (col == null) {
        return count;
        }
        Iterator it = col.iterator();
        while (it.hasNext()) {
        Object elt = it.next();
//obj를 참조하는 equals가 null이
        if ((null == obj && null == elt) || (null != obj && obj.equals(elt))) {
        count++;
        }
        }
        return count;
        }

```
obj가 null인지 검사 후 참조해야 한다.

### 부적절한 자원 해제

```
프로그램의 자원, 예를 들면 열린 파일디스크립터(Open File Descriptor), 힙 메모리(Heap Memory),
소켓(Socket) 등은 유한한 자원이다. 이러한 자원을 할당받아 사용한 후, 더 이상 사용하지 않는 경우
에는 적절히 반환하여야 하는데, 프로그램 오류 또는 에러로 사용이 끝난 자원을 반환하지 못하는
경우이다.
```

#### 취약코드
```java
InputStream in = null;
        OutputStream out = null;
        try {
        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputFile);
        ...
        FileCopyUtils.copy(fis, os);
//자원반환 실행 전에 오류가 발생할 경우 자원이 반환되지 않으며, 할당된 모든 자원을 반환해야
        한다.
        in.close();
        out.close();
        } catch (IOException e) {
        logger.error(e);
        }

```
try구문 내 처리 중 오류가 발생할 경우, close()메서드가 실행되지 않아 사용한 자원이 반환되지
않을 수 있다.

#### 안전한 코드
```java
InputStream in = null;
        OutputStream out = null;
        try {
        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputFile);
        ...
        FileCopyUtils.copy(fis, os);
        } catch (IOException e) {
        logger.error(e);
//항상 수행되는 finally 블록에서 할당받은 모든 자원에 대해 각각 null검사를 수행 후 예외처리를 하여
        자원을 해제하여야 한다.
        } finally {
        if (in != null) {
        try {
        in.close();
        } catch (IOException e) {
        logger.error(e);
        }
        }
        if (out != null) {
        try {
        out.close();
        } catch (IOException e) {
        logger.error(e);
        }
        }
        }
```
예외상황이 발생하여 함수가 종료될 때, 예외의 발생 여부와 상관없이 항상 실행되는 finally 블록에서
할당받은 모든 자원을 반드시 반환하도록 한다.

### 부적절한 자원 해제

```
프로그램의 자원, 예를 들면 열린 파일디스크립터(Open File Descriptor), 힙 메모리(Heap Memory),
소켓(Socket) 등은 유한한 자원이다. 이러한 자원을 할당받아 사용한 후, 더 이상 사용하지 않는 경우
에는 적절히 반환하여야 하는데, 프로그램 오류 또는 에러로 사용이 끝난 자원을 반환하지 못하는
경우이다.
```

#### 취약코드
```java
InputStream in = null;
        OutputStream out = null;
        try {
        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputFile);
        ...
        FileCopyUtils.copy(fis, os);
//자원반환 실행 전에 오류가 발생할 경우 자원이 반환되지 않으며, 할당된 모든 자원을 반환해야
        한다.
        in.close();
        out.close();
        } catch (IOException e) {
        logger.error(e);
        }

```
try구문 내 처리 중 오류가 발생할 경우, close()메서드가 실행되지 않아 사용한 자원이 반환되지
않을 수 있다.

#### 안전한 코드
```java
InputStream in = null;
        OutputStream out = null;
        try {
        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputFile);
        ...
        FileCopyUtils.copy(fis, os);
        } catch (IOException e) {
        logger.error(e);
//항상 수행되는 finally 블록에서 할당받은 모든 자원에 대해 각각 null검사를 수행 후 예외처리를 하여
        자원을 해제하여야 한다.
        } finally {
        if (in != null) {
        try {
        in.close();
        } catch (IOException e) {
        logger.error(e);
        }
        }
        if (out != null) {
        try {
        out.close();
        } catch (IOException e) {
        logger.error(e);
        }
        }
        }
```
예외상황이 발생하여 함수가 종료될 때, 예외의 발생 여부와 상관없이 항상 실행되는 finally 블록에서
할당받은 모든 자원을 반드시 반환하도록 한다.

## 캡슐화
중요한 데이터 또는 기능성을 불충분하게 캡슐화하거나 잘못 사용함으로써 발생하는 보안약점으로
정보노출, 권한문제 등이 발생할 수 있다.

### 잘못된 세션에 의한 데이터 정보노출

```
다중 스레드 환경에서는 싱글톤(Singleton)6) 객체 필드에 경쟁조건(Race Condition)이 발생할 수
있다. 따라서, 다중 스레드 환경인 Java의 서블릿(Servlet) 등에서는 정보를 저장하는 멤버변수가
포함되지 않도록 하여, 서로 다른 세션에서 데이터를 공유하지 않도록 해야 한다.
```

#### 취약코드
```java
<%@page import="javax.xml.namespace.*"%>
<%@page import="gov.mogaha.ntis.web.frs.gis.cmm.util.*" %>
<%!// JSP에서 String 필드들이 멤버 변수로 선언됨
        String username = "/";
        String imagePath = commonPath + "img/";
        String imagePath_gis = imagePath + "gis/cmm/btn/";
        ……
        %>
```
JSP 선언부(<%! 소스코드 %>)에 선언한 변수는 해당 JSP에 접근하는 모든 사용자에게 공유된다.
먼저 호출한 사용자가 값을 설정하고 사용하기 전에 다른 사용자의 호출이 발생하게 되면, 뒤에 호출
한 사용자가 설정한 값이 모든 사용자에게 적용되게 된다.


#### 안전한 코드
```java
<%@page import="javax.xml.namespace.*"%>
<%@page import="gov.mogaha.ntis.web.frs.gis.cmm.util.*" %>
<%
// JSP에서 String 필드들이 로컬 변수로 선언됨
        String commonPath = "/";
        String imagePath = commonPath + "img/";
        String imagePath_gis = imagePath + "gis/cmm/btn/";
        ……
        %>
```
JSP의 서블릿(<% 소스코드 %>)에 정의한 변수는 _jspService 메소드의 지역변수로 선언되므로
공유가 발생하지 않아 안전하다.

### 제거되지 않고 남은 디버그 코드

```
디버깅 목적으로 삽입된 코드는 개발이 완료되면 제거해야 한다. 디버그 코드는 설정 등의 민감한
정보를 담거나 시스템을 제어하게 허용하는 부분을 담고 있을 수 있다. 만일, 남겨진 채로 배포될
경우, 공격자가 식별 과정을 우회하거나 의도하지 않은 정보와 제어 정보가 노출될 수 있다.
```

#### 취약코드
```java
class Base64 {
    public static void main(String[] args) {
        if (debug) {
            byte[] a = { (byte) 0xfc, (byte) 0x0f, (byte) 0xc0 };
            byte[] b = { (byte) 0x03, (byte) 0xf0, (byte) 0x3f };
……
        }
    }
    public void otherMethod() { … }
}
```
main() 메소드 내에 화면에 출력하는 디버깅 코드를 포함하고 있다. J2EE의 경우
main() 메소드 사용이 필요 없으며, 개발자들이 콘솔 응용프로그램으로 화면에 디버깅코드를
사용하는 경우가 일반적이다.


#### 안전한 코드
```java
class Base64 {
    public void otherMethod() { … }
}
```
J2EE와 같은 응용프로그램에서 main() 메소드는 삭제한다. J2EE의 main() 메소드의
경우 디버깅 코드인 경우가 일반적이다.

### 시스템 데이터 정보노출

```
시스템, 관리자, DB정보 등 시스템의 내부 데이터가 공개되면, 공격자에게 또 다른 공격의 빌미를
제공하게 된다.

```

#### 취약코드
```java
catch (IOException e) {
//오류 발생시 화면에 출력된 시스템 정보를 통해 다른 공격의 빌미를 제공 한다.
        System.err.print(e.getMessage());
        }
```
예외 발생 시 getMessage()를 이용한 오류메시지를 통해 오류와 관련된 시스템 정보 등 민감한
정보가 유출될 수 있다.

#### 안전한 코드
```java
catch (IOException e) {
//오류와 관련된 최소한의 정보만을 제공하도록한다.
        logger.error("IOException Occured");
        }
```
가급적이면 공격의 빌미가 될 수 있는 오류와 관련된 상세한 정보는 사용자에게 노출되지 않도록
최소한의 정보만을 제공한다.

### Public 메소드부터 반환된 Private 배열

```
private로 선언된 배열을 public으로 선언된 메소드를 통해 반환(return)하면, 그 배열의 레퍼런스가
외부에 공개되어 외부에서 배열수정과 객체 속성변경이 가능해진다.
```

#### 취약코드
```java
// private 인 배열을 public인 메소드가 return한다.
private Color[] colors;
public Color[] getUserColors(Color[] userColors) { return colors; }
```
멤버 변수 colors는 private로 선언되었지만 public으로 선언된 getUserColors
메소드를 통해 private 배열에 대한 reference를 얻을 수 있다. 이를 통해 의도하지 않은 수정이
발생할 수 있다.

#### 안전한 코드
```java
private Color[] colors;
//메소드를 private으로 하거나, 복제본 반환, 수정하는 public 메소드를 별도로 만든다.
public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Color[] newColors = getUserColors();
        ......
        }
public Color[] getUserColors(Color[] userColors) {
//배열을 복사한다.
        Color[] colors = new Color [userColors.length];
        for (int i = 0; i < colors.length; i++)
//clone()메소드를 이용하여 배열의 원소도 복사한다.
        colors[i] = this.colors[i].clone();
        return colors;
        }

```
private배열에 대한 복사본을 만들고, 복사된 배열의 원소로는 clone() 메소드를 통해 private
배열의 원소의 복사본을 만들어 저장하여 반환하도록 작성하면, private선언된 배열과 원소에 대한
의도하지 않은 수정을 방지 할 수 있다.

###  Private 배열에 Public 데이터 할당

```
public으로 선언된 메소드의 인자가 private선언된 배열에 저장되면, private배열을 외부에서
접근하여 배열수정과 객체 속성변경이 가능해진다.

```

#### 취약코드
```java
//userRoles 필드는 private이지만, public인 setUserRoles()를 통해 외부의 배열이 할당되면, 사실상
public 필드가 된다.
private UserRole[] userRoles;
public void setUserRoles(UserRole[] userRoles) {
        this.userRoles = userRoles;
        }
```
멤버 변수 userRoles는 private로 선언되었지만 public으로 선언된 setUserRoles
메소드를 통해 인자가 할당되어 배열의 원소를 외부에서 변경할 수 있다. 이를 통해 의도하지 않은
배열과 원소에 대한 객체속성 수정이 발생할 수 있다.
#### 안전한 코드
```java
//객체가 클래스의 private member를 수정하지 않도록 한다.
private UserRole[] userRoles;
public void setUserRoles(UserRole[] userRoles) {
        this.userRoles = new UserRole[userRoles.length];
        for (int i = 0; i < userRoles.length; ++i)
        this.userRoles[i] = userRoles[i].clone();
        }
```
인자로 들어온 배열의 복사본을 생성하고 clone() 메소드를 통해 복사된 원소를 저장하도록 하여
private변수에 할당하면 private으로 할당된 배열과 원소에 대한 의도하지 않은 수정을 방지 할 수
있다

## API 오용
의도된 사용에 반하는 방법으로 API를 사용하거나, 보안에 취약한 API를 사용하여 발생할 수 있는
보안약점이다.
### DNS lookup에 의존한 보안결정

```
공격자가 DNS 엔트리를 속일 수 있으므로 도메인명에 의존에서 보안결정(인증 및 접근 통제 등)을
하지 않아야 한다. 만약, 로컬 DNS 서버의 캐시가 공격자에 의해 오염된 상황이라면, 사용자와 특정
서버간의 네트워크 트래픽이 공격자를 경유하도록 할 수도 있다. 또한, 공격자가 마치 동일 도메인에
속한 서버인 것처럼 위장할 수도 있다.
```

#### 취약코드
```java
public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException {
        boolean trusted = false;
        String ip = req.getRemoteAddr();
        InetAddress addr = InetAddress.getByName(ip);
//도메인은 공격자에 의해 실행되는 서버의 DNS가 변경될 수 있으므로 안전하지 않다.
        if (addr.getCanonicalHostName().endsWith("trustme.com"))
```
도메인명을 통해 해당 요청을 신뢰할 수 있는지를 검사한다. 그러나 공격자는 DNS
캐쉬 등을 조작해서 쉽게 이러한 보안 설정을 우회할 수 있다.
#### 안전한 코드
```java
public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException {
        String ip = req.getRemoteAddr();
        if (ip == null || "".equals(ip)) return ;
//이용하려는 실제 서버의 IP 주소를 사용하여 DNS변조에 방어한다.
        String trustedAddr = "127.0.0.1";
        if (ip.equals(trustedAddr)) {
        do_something_for_Trust_System();
        }
```
DNS lookup에 의한 호스트 이름 비교를 하지 않고, IP 주소를 직접
비교하도록 수정한다.

# Oracle Secure Coding Guidelines for Java SE

## 서비스 거부 (section 1)
```
시스템에 대한 입력은 서비스를 요청하는 데 사용된 리소스와 불균형한 과도한 리소스 소비가 발생하지 않도록 확인해야 합니다.
영향을 받는 일반적인 리소스는 CPU 주기, 메모리, 디스크 공간 및 파일 설명자입니다.
```

### DOS-2: 모든 경우에 리소스 해제
```
오류를 줄이려면 중복을 최소화하고 리소스 처리 문제를 분리해야 합니다. 
Execute Around Method 패턴은 짝을 이룬 획득 및 릴리스 작업을 추출하는 탁월한 방법을 제공합니다. 
패턴은 Java SE 8 람다 기능을 사용하여 간결하게 사용할 수 있습니다.
```

#### 안전한 코드
```java
public R readFileBuffered(
        InputStreamHandler handler
        ) throws IOException {
        try (final InputStream in = Files.newInputStream(path)) { //try-with-resource 구문은 많은 리소스 유형의 릴리스를 자동으로 처리합니다.
        handler.handle(new BufferedInputStream(in));
        }
        }
```

### DOS-3: 리소스 제한 검사에서 정수 오버플로가 발생해서는 안 됩니다.
```java
private void checkGrowBy(long extra) {
    if (extra < 0 || current > max - extra) { //값이 크면 current + max항상 보다 작은 음수 값으로 오버플로될 수 있습니다 max
        throw new IllegalArgumentException();
    }
}
```

```java
private void checkGrowBy(long extra) { //성능이 특정 문제가 아닌 경우 장황한 접근 방식은 임의 크기의 정수를 사용하는 것입니다.
    BigInteger currentBig = BigInteger.valueOf(current);
    BigInteger maxBig     = BigInteger.valueOf(max);
    BigInteger extraBig   = BigInteger.valueOf(extra);

    if (extra < 0 ||
        currentBig.add(extraBig).compareTo(maxBig) > 0) {
            throw new IllegalArgumentException();
    }
    
}
```

## 기밀정보 (section 2)
```
기밀 데이터는 제한된 컨텍스트 내에서만 읽을 수 있어야 합니다.
신뢰할 수 있는 데이터는 변조에 노출되어서는 안 됩니다. 
권한 있는 코드는 의도된 인터페이스를 통해 실행되어서는 안 됩니다.
```

## 주입 및 포함 (section 3)
```
매우 일반적인 공격 형태는 특정 프로그램이 예상치 못한 제어 변경을 일으키는 방식으로 조작된 데이터를 해석하도록 하는 것입니다. 
일반적으로 항상 그런 것은 아니지만 여기에는 텍스트 형식이 포함됩니다.
```
### INJECT-2: 동적 SQL 피하기
#### 안전한 코드
```java
String sql = "SELECT * FROM User WHERE userId = ?"; 
PreparedStatement stmt = con.prepareStatement(sql); //PreparedStatement를 올바르게 사용하는 예
stmt.setString(1, userId); 
ResultSet rs = prepStmt.executeQuery();
```

## 접근성 및 확장성 (section 4)
```
시스템 보안 작업은 코드의 "공격 표면"을 줄임으로써 더 쉬워집니다.
```
###  ​​EXTEND-2: 패키지 접근성 제한
```
컨테이너는 package.access 보안 속성 에 추가하여 구현 코드를 숨길 수 있습니다. 
이 속성은 지정된 패키지 계층 구조에 대한 리플렉션을 사용하고 연결하는 다른 클래스 로더의 신뢰할 수 없는 클래스를 방지합니다. 
이 속성을 설정하기 전에 신뢰할 수 없는 컨텍스트에서 패키지에 액세스할 수 없도록 주의해야 합니다.
```
#### 안전한 코드
```java
private static final String PACKAGE_ACCESS_KEY = "package.access"; //  package.access보안 속성 에 추가하는 방법
static {
        String packageAccess = java.security.Security.getProperty(
        PACKAGE_ACCESS_KEY
        );
        java.security.Security.setProperty(
        PACKAGE_ACCESS_KEY,
        (
        (packageAccess == null ||
        packageAccess.trim().isEmpty()) ?
        "" :
        (packageAccess + ",")
        ) +
        "xx.example.product.implementation."
        );
        }
```

###  EXTEND-5: 클래스 및 메서드의 확장성 제한
```
상속을 위한 클래스 및 메서드를 설계하거나 final로 선언합니다. 
최종이 아닌 클래스나 메서드는 공격자가 악의적으로 재정의할 수 있습니다. 
서브클래싱을 허용하지 않는 클래스는 구현하기 쉽고 안전한지 확인합니다. 상속보다 구성을 선호합니다.
```
#### 안전한 코드
```java
// Unsubclassable class with composed behavior.
public final class SensitiveClass {

    private final Behavior behavior;

    // Hide constructor.
    private SensitiveClass(Behavior behavior) {
        this.behavior = behavior;
    }

    // Guarded construction.
    public static SensitiveClass newSensitiveClass(
            Behavior behavior
    ) {
        // ... validate any arguments ...

        // ... perform security checks ...

        return new SensitiveClass(behavior);
    }
}
```

## 입력 검증 (section 5)
```
Java 문화의 특징은 엄격한 메서드 매개변수 검사를 사용하여 견고성을 향상시킨다는 것입니다. 
보다 일반적으로 외부 입력의 유효성을 검사하는 것은 보안의 중요한 부분입니다.
```
### INPUT-3: 네이티브 메소드 주변의 래퍼 정의
```
컨테이너는 package.access 보안 속성 에 추가하여 구현 코드를 숨길 수 있습니다. 
이 속성은 지정된 패키지 계층 구조에 대한 리플렉션을 사용하고 연결하는 다른 클래스 로더의 신뢰할 수 없는 클래스를 방지합니다. 
이 속성을 설정하기 전에 신뢰할 수 없는 컨텍스트에서 패키지에 액세스할 수 없도록 주의해야 합니다.
```
#### 안전한 코드
```java
public final class NativeMethodWrapper {

    // private native method
    private native void nativeOperation(byte[] data, int offset,
                                        int len);

    // wrapper method performs checks
    public void doOperation(byte[] data, int offset, int len) {
        // copy mutable input
        data = data.clone();

        // validate input
        // Note offset+len would be subject to integer overflow.
        // For instance if offset = 1 and len = Integer.MAX_VALUE,
        //   then offset+len == Integer.MIN_VALUE which is lower
        //   than data.length.
        // Further,
        //   loops of the form
        //       for (int i=offset; i<offset+len; ++i) { ... }
        //   would not throw an exception or cause native code to
        //   crash.

        if (offset < 0 || len < 0 || offset > data.length - len) {
            throw new IllegalArgumentException();
        }

        nativeOperation(data, offset, len);
    }
}
```

## 가변성 (section 6)
```
변경 가능성은 무해한 것처럼 보이지만 놀라울 정도로 다양한 보안 문제를 일으킬 수 있습니다.
```
### MUTABLE-2: 변경 가능한 출력 값의 복사본 만들기
```
메서드가 내부 변경 가능한 개체에 대한 참조를 반환하면 클라이언트 코드가 인스턴스의 내부 상태를 수정할 수 있습니다. 
상태를 공유하려는 의도가 아니라면 변경 가능한 개체를 복사하고 복사본을 반환합니다.
```
#### 안전한 코드
```java
public class CopyOutput { //신뢰할 수 있는 변경 가능한 개체의 복사본을 만들려면 복사 생성자 또는 복제 메서드를 호출합니다.
    private final java.util.Date date;
    ...
    public java.util.Date getDate() {
        return (java.util.Date)date.clone();
    }
}
```

### MUTABLE-5: 입력 참조 개체에서 재정의할 수 있는 경우 동일성을 신뢰하지 마십시오.
```
재정의 가능한 메서드가 예상대로 작동하지 않을 수 있습니다.

예를 들어, 동일성 평등 동작을 예상할 때 Object.equals다른 객체에 대해 true를 반환하도록 재정의될 수 있습니다. 
특히 에서 키로 사용 Map되는 객체는 액세스해서는 안 되는 다른 객체로 자신을 전달할 수 있습니다.
```

#### 안전한 코드
```java
private final Map<Window,Extra> extras = new IdentityHashMap<>(); //가능한 경우 와 같이 동일성을 적용하는 컬렉션 구현을 사용하십시오 IdentityHashMap.

public void op(Window window) {
        // Window.equals may be overridden,
        // but safe as we are using IdentityHashMap
        Extra extra = extras.get(window);
        }
```

#### 안전한 코드
```java
//컬렉션을 사용할 수 없는 경우 공격자가 액세스할 수 없는 패키지 개인 키를 사용합니다.
public class Window {
    /* pp */ class PrivateKey {
        // Optionally, refer to real object.
        /* pp */ Window getWindow() {
            return Window.this;
        }
    }
    /* pp */ final PrivateKey privateKey = new PrivateKey();

    private final Map<Window.PrivateKey,Extra> extras =
            new WeakHashMap<>();
    ...
}

public class WindowOps {
    public void op(Window window) {
        // Window.equals may be overridden,
        // but safe as we don't use it.
        Extra extra = extras.get(window.privateKey);
        ...
    }
}
```

### MUTABLE-7: 신뢰할 수 없는 객체의 출력을 입력으로 처리
```
재정의 가능한 메서드가 예상대로 작동하지 않을 수 있습니다.

예를 들어, 동일성 평등 동작을 예상할 때 Object.equals다른 객체에 대해 true를 반환하도록 재정의될 수 있습니다. 
특히 에서 키로 사용 Map되는 객체는 액세스해서는 안 되는 다른 객체로 자신을 전달할 수 있습니다.
```

#### 안전한 코드
```java
// 입력 개체에 대한 위의 지침은 신뢰할 수 없는 개체에서 반환될 때 적용됩니다. 
// 적절한 복사 및 검증이 적용되어야 합니다.
private final Date start;
private Date end;

public void endWith(Event event) throws IOException {
        Date end = new Date(event.getDate().getTime());
        if (end.before(start)) {
        throw new IllegalArgumentException("...");
        }
        this.end = end;
        }
```

### MUTABLE-9: 공개 정적 필드를 최종으로 설정
```
호출자는 공개가 아닌 정적 필드에 쉽게 액세스하고 수정할 수 있습니다. 
접근이나 수정을 막을 수 없으며 새로 설정한 값을 확인할 수 없습니다. 
하위 분류 가능한 유형이 있는 필드는 악의적으로 구현된 개체로 설정될 수 있습니다.
```

#### 안전한 코드
```java
public class Files { // 항상 public static 필드를 final로 선언하십시오.
    public static final String separator = "/";
    public static final String pathSeparator = ":";
}
```

## 객체 구성 (section 7)
```
건설 중 물체는 존재하지만 사용할 준비가 되지 않은 어색한 단계에 있습니다. 
이러한 어색함은 일반적인 방법의 어려움 외에도 몇 가지 더 많은 어려움을 제공합니다.
```

### OBJECT-3: 부분적으로 초기화되지 않은 최종 클래스의 인스턴스로부터 방어
```
final이 아닌 클래스의 생성자가 예외를 throw하면 공격자는 해당 클래스의 부분적으로 초기화된 인스턴스에 대한 액세스를 시도할 수 있습니다. 
생성자가 성공적으로 완료될 때까지 final이 아닌 클래스는 완전히 사용할 수 없는 상태로 유지됩니다.
```
#### 안전한 코드
```java
//  Object생성자가 완료 되기 전에 예외를 throw하여 하위 클래스화 가능한 클래스의 생성을 방지할 수 있습니다 .
// 이렇게 하려면 this()또는 에 대한 호출에서 평가되는 식에서 검사를 수행합니다 super().
public abstract class ClassLoader {
    protected ClassLoader() {
        this(securityManagerCheck());
    }
    private ClassLoader(Void ignored) {
        // ... continue initialization ...
    }
    private static Void securityManagerCheck() {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        return null;
    }
}
```

## 직렬화 및 역직렬화 (section 8)
```
참고: 신뢰할 수 없는 데이터의 역직렬화는 본질적으로 위험하므로 피해야 합니다.

Java 직렬화는 Java 언어의 필드 액세스 제어 메커니즘을 우회하는 클래스에 대한 인터페이스를 제공합니다. 
따라서 직렬화 및 역직렬화를 수행할 때 주의해야 합니다. 
또한 신뢰할 수 없는 데이터의 역직렬화는 가능한 한 피해야 하며 피할 수 없는 경우에는 주의해서 수행해야 합니다
```

### SERIAL-3: 객체 생성과 동일한 보기 역직렬화
```
역직렬화는 해당 클래스의 생성자를 호출하지 않고 클래스의 새 인스턴스를 만듭니다. 
따라서 deserialization은 일반 구성처럼 작동하도록 설계해야 합니다.
```

#### 안전한 코드
```java
//기본 역직렬화이며 ObjectInputStream.defaultReadObject비일시적 필드에 임의의 개체를 할당할 수 있으며 반드시 반환되지는 않습니다.
//ObjectInputStream.readFields필드에 할당하기 전에 복사를 삽입하는 대신 사용하십시오.
public final class ByteString implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] data;
    public ByteString(byte[] data) {
        this.data = data.clone(); // Make copy before assignment.
    }
    private void readObject(
            java.io.ObjectInputStream in
    ) throws java.io.IOException, ClassNotFoundException {
        java.io.ObjectInputStreadm.GetField fields =
                in.readFields();
        this.data = ((byte[])fields.get("data")).clone();
    }
    ...
}
```

### SERIAL-4: 직렬화 및 역직렬화 중에 클래스에 적용된 SecurityManager 검사 복제
```
공격자가 직렬화 또는 역직렬화를 사용하여 SecurityManager클래스에서 시행 되는 검사 를 우회하는 것을 방지합니다 . 
특히 직렬화 가능한 클래스 SecurityManager가 생성자에서 검사를 시행하는 경우 readObject또는 readObjectNoData메서드 구현 에서 동일한 검사를 시행합니다 .
```

#### 안전한 코드
```java
public final class SensitiveClass implements java.io.Serializable {
    public SensitiveClass() {
        // permission needed to instantiate SensitiveClass
        securityManagerCheck();

        // regular logic follows
    }

    // implement readObject to enforce checks
    //   during deserialization
    private void readObject(java.io.ObjectInputStream in) {
        // duplicate check from constructor
        securityManagerCheck();

        // regular logic follows
    }
}
```

## 액세스 제어 (section 9)
```
이 섹션의 많은 지침은 SecurityManager를 사용하여 보안 검사를 수행하고 코드에 대한 권한을 높이거나 제한하는 방법을 다룹니다. 
SecurityManager는 부채널 공격이나 Row hammer와 같은 하위 수준 문제와 같은 문제에 대한 보호를 제공하지 않으며 제공할 수도 없으며 완전한 프로세스 내 격리를 보장할 수도 없습니다. 
민감한 정보가 있는 신뢰할 수 있는 코드에서 신뢰할 수 없는 코드를 분리하려면 별도의 프로세스(JVM)를 사용해야 합니다. 운영 체제 또는 컨테이너에서 사용할 수 있는 낮은 수준의 격리 메커니즘을 사용하는 것도 권장됩니다.
```

### ACCESS-1: 권한 확인 방법 이해
```
표준 보안 검사는 호출 스택의 각 프레임에 필요한 권한이 있는지 확인합니다. 
즉, 현재 시행 중인 권한 은 현재 액세스 제어 컨텍스트에서 각 프레임의 권한의 교차점 입니다. 
프레임에 권한이 없으면 스택의 위치에 관계없이 현재 컨텍스트에 해당 권한이 없습니다.
```

#### 안전한 코드
```java
package xx.lib; //라이브러리를 통해 보안 작업을 간접적으로 사용하는 애플리케이션을 고려하십시오.

public class LibClass {
    private static final String OPTIONS = "xx.lib.options";

    public static String getOptions() {
        // checked by SecurityManager
        return System.getProperty(OPTIONS);
    }
}

package yy.app;

class AppClass {
    public static void main(String[] args) {
        System.out.println(
                xx.lib.LibClass.getOptions()
        );
    }
}
```

### ACCESS-4: doPrivileged를 통해 권한을 제한하는 방법을 숙지하십시오.
```
권한이 프레임 교차로 제한되므로 프레임이 AccessControlContext없는(제로) 프레임을 나타내는 인공적인 것은 모든 권한을 의미합니다.
```

#### 안전한 코드
```java
//AccessControlContext프레임이 포함 된 인공 컨텍스트를 사용하여 모든 권한을 제거할 수 있습니다 ProtectionDomain.
private static final AccessControlContext allPermissionsAcc =
        new AccessControlContext(
        new java.security.ProtectionDomain[0]
        );
        void someMethod(PrivilegedAction<Void> action) {
        AccessController.doPrivileged(action, allPermissionsAcc);
        AccessController.doPrivileged(action, null);
        AccessController.doPrivileged(action);
        }
```