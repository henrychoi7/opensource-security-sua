func main(){

	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")

	// SQLI를 시도하려 해도 '?' 때문에 쿼리로 인식하지 않음
	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = ?"
	row, _ = db.QueryContext(ctx, query, customerId)

}
