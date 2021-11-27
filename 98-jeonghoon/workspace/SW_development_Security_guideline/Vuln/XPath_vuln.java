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
// 안전하지 않은 질의문이 담긴 expr을 평가하여 결과를 result에 저장한다.
Object result = expr.evaluate(doc, XPathConstants.NODESET);
// result의 결과를 NodeList 타입으로 변환하여 nodes 저장한다.
NodeList nodes = (NodeList) result;
for (int i=0; i<nodes.getLength(); i++) {
String value = nodes.item(i).getNodeValue();
if (value.indexOf(">") < 0) {
// 공격자가 이름과 패스워드를 확인할 수 있다. System.out.println(value);
}
}
