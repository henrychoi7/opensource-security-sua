1. // 외부 입력 값을 검증하지 않고 XQuery 표현식에 사용한다.
2. String name = props.getProperty("name");
3. .......
4. // 외부 입력 값에 의해 쿼리 구조가 변경 되어 안전하지 않다.
5. String es = "doc('users.xml')/userlist/user[uname='"+name+"']";
6. XQPreparedExpression expr = conn.prepareExpression(es);
7. XQResultSequence result = expr.executeQuery();
