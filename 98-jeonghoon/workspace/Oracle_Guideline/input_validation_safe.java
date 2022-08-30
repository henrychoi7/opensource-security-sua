// private로 선언하고 public Java 기반 래퍼 메소드를 통해 기능을 노출한다. 기본 메서드를 호출하기 전에 필요한 모든 입력 유효성 검사를 안전하게 수행할수 있다.

public final class NativeMethodWrapper {

    // private native method
    private native void nativeOperation(byte[] data, int offset,
                                        int len);

    // wrapper method performs checks
    public void doOperation(byte[] data, int offset, int len) {
        // copy mutable input
        data = data.clone();

        // validate input
        // Note offset+len would be subject to integer overflow.
        // For instance if offset = 1 and len = Integer.MAX_VALUE,
        //   then offset+len == Integer.MIN_VALUE which is lower
        //   than data.length.
        // Further,
        //   loops of the form
        //       for (int i=offset; i<offset+len; ++i) { ... }
        //   would not throw an exception or cause native code to
        //   crash.

        if (offset < 0 || len < 0 || offset > data.length - len) {
              throw new IllegalArgumentException();
        }

        nativeOperation(data, offset, len);
    }
}
