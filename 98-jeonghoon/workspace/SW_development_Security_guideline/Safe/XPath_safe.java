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
// vars.put("loginID", nm);
vars.put("password", pw);
// 파라미터화된 쿼리를 실행하므로 외부값을 검증없이 사용하여도 안전하다.
Nodes results = xquery.execute(doc, null, vars).toNodes();
for (int i=0; i<results.size(); i++) {
System.out.println(results.get(i).toXML());
}

// XPath 삽입을 유발할 수 있는 문자들을 입력값에서 제거
public String XPathFilter(String input) {
if (input != null) return input.replaceAll("[',￦￦[]", "");
else return "";
}
......
// 외부 입력값에 사용
String nm = XPathFilter(props.getProperty("name"));
String pw = XPathFilter(props.getProperty("password"));
......
XPathFactory factory = XPathFactory.newInstance();
XPath xpath = factory.newXPath();
......
//외부 입력값인 nm, pw를 검증하여 쿼리문을 생성하므로 안전하다.
XPathExpression expr = xpath.compile("//users/user[login/text()='"+nm+"' and
password/text()='"+pw+"']/home_dir/text()");
Object result = expr.evaluate(doc, XPathConstants.NODESET);
NodeList nodes = (NodeList) result;
for (int i=0; i<nodes.getLength(); i++) {
String value = nodes.item(i).getNodeValue();
if (value.indexOf(">") < 0) {
System.out.println(value);
}
}
