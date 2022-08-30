# 임의 크기 정수를 사용하여 overflow 방지
# private void checkGrowBy(long extra) {
    BigInteger currentBig = BigInteger.valueOf(current);
    BigInteger maxBig     = BigInteger.valueOf(max);
    BigInteger extraBig   = BigInteger.valueOf(extra);

    if (extra < 0 ||
        currentBig.add(extraBig).compareTo(maxBig) > 0) {
            throw new IllegalArgumentException();
    }
}
