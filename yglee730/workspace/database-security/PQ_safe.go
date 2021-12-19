// 파라미터를 받아서 매개변수화 시켜 '?' 변수에 할당
// SQL Injection 예방
customerName := r.URL.Query().Get("name")
db.Exec("UPDATE creditcards SET name=? WHERE customerId=?", customerName, 233, 90)
