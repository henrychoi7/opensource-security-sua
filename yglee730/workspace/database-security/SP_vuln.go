// 입력값을 따로 검증하지 않아, 사용자 ID에 대한 모든 정보에 액세스 할 수 있음
SELECT * FROM tblUsers WHERE userId = $user_input
