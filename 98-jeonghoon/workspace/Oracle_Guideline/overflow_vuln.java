# 값이 크면 current + max 보다 작은 음수값으로 overflow될수 있다.
private void checkGrowBy(long extra) {
    if (extra < 0 || current > max - extra) {
        throw new IllegalArgumentException();
    }
}
