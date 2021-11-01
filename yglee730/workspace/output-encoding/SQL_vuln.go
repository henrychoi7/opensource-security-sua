func main(){

	ctx:=context.Background()
	customerId := r.URL.Query.Get("id")

	// customerId의 변수 값 그대로 쿼리에 주입됨
	query := "SELECT number, expireDate, cvv FROM creditcards WHERE customerId = "+customerId

	row, _ = db.QueryContext(ctx, query)

}
