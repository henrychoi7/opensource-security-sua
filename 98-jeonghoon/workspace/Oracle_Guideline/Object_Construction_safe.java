// JDK 6부터는 Object생성자가 완료 되기 전에 예외를 throw하여 하위 클래스화 가능한 클래스의 생성을 방지할 수 있습니다 . 이렇게 하려면 this()또는 에 대한 호출에서 평가되는 식에서 검사를 수행합니다 super().

// non-final java.lang.ClassLoader
public abstract class ClassLoader {
    protected ClassLoader() {
        this(securityManagerCheck());
    }
    private ClassLoader(Void ignored) {
        // ... continue initialization ...
    }
    private static Void securityManagerCheck() {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        return null;
    }
}

// 접근 방식은 "구현에 대한 포인터"(또는 "pimpl")를 사용하는 것입니다. 클래스의 핵심은 인터페이스 클래스 전달 메서드 호출과 함께 비공개 클래스로 이동됩니다. 완전히 초기화되기 전에 클래스를 사용하려고 하면 NullPointerException. 이 접근 방식은 복제 및 역직렬화 공격을 처리하는 데에도 좋습니다.
public abstract class ClassLoader {

    private final ClassLoaderImpl impl;

    protected ClassLoader() {
        this.impl = new ClassLoaderImpl();
    }
    protected final Class defineClass(...) {
        return impl.defineClass(...);
    }
}

/* pp */ class ClassLoaderImpl {
    /* pp */ ClassLoaderImpl() {
        // permission needed to create ClassLoader
        securityManagerCheck();
        init();
    }

    /* pp */ Class defineClass(...) {
        // regular logic follows
        ...
    }
}

