// 변경 가능한 클래스의 경우 "initialized" flag를 휘발성으로 만들어 관계를 만드는게 좋다.
public class NonFinal {

    private volatile boolean initialized;

    // sole constructor
    public NonFinal() {
        securityManagerCheck();

        // ... initialize class ...

        // Last action of constructor.
        this.initialized = true;
    }

    public void doSomething() {
        checkInitialized();
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new SecurityException(
                "NonFinal not initialized"
            );
        }
    }
}
