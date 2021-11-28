// 저장 프로시저를 사용하요 웹 응용 프로그램에 대한 새로운 보호 계층을 만듬

// 저장 프로시저를 사용하면 일반 쿼리를 사용하는 대신 쿼리에 대한 특정 보기를 만들어 
// 민감한 정보가 보관되지 않도록 할 수 있음
CREATE PROCEDURE db.getName @userId int = NULL
AS
    SELECT name, lastname FROM tblUsers WHERE userId = @userId
GO
