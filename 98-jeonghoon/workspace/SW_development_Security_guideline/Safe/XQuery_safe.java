1. // blingString 함수로 쿼리 구조가 변경되는 것을 방지한다.
2. String name = props.getProperty("name");
3. .......
4. String es = "doc('users.xml')/userlist/user[uname='$xname']";
5. XQPreparedExpression expr = conn.prepareExpression(es);
6. expr.bindString(new QName("xname"), name, null);
7. XQResultSequence result = expr.executeQuery();

