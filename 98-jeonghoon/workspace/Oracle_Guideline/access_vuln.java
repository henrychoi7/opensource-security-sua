// 최종이 아닌 클래스나 메서드는 공격자가 악의적으로 재정의할 수 있다.
// Unsubclassable class with composed behavior.
public final class SensitiveClass {

    private final Behavior behavior;

    // Hide constructor.
    private SensitiveClass(Behavior behavior) {
       this.behavior = behavior;
    }

    // Guarded construction.
    public static SensitiveClass newSensitiveClass(
        Behavior behavior
    ) {
        // ... validate any arguments ...

        // ... perform security checks ...

        return new SensitiveClass(behavior);
    }
}
