# 예상치 못한 부동 소수점 숫자의 추가 처리를 차단할수 있는 코드
if (Double.isNaN(untrusted_double_value)) {
    // specific action for non-number case
}

if (Double.isInfinite(untrusted_double_value)){
    // specific action for infinite case
}
