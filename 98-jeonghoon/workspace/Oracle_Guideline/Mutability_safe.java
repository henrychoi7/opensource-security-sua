// 신뢰할 수 있는 변경 가능한 개체의 복사본을 만들려면 복사 생성자 또는 복제 메서드를 호출해야한다.
public class CopyOutput {
    private final java.util.Date date;
    ...
    public java.util.Date getDate() {
        return (java.util.Date)date.clone();
    }
}

//신뢰할 수 없는 변경 가능한 객체의 복사본을 만들려면 복사 생성자 또는 생성 메서드를 호출해야한다.
public final class CopyMutableInput {
    private final Date date;

    // java.util.Date is mutable
    public CopyMutableInput(Date date) {
        // create copy
        this.date = new Date(date.getTime());
    }
}

// 입력 개체에 대한 위의 지침은 신뢰할 수 없는 개체에서 반환될 때 적용됩니다. 적절한 복사 및 검증이 적용되어야한다.

private final Date start;
private Date end;

public void endWith(Event event) throws IOException {
    Date end = new Date(event.getDate().getTime());
    if (end.before(start)) {
        throw new IllegalArgumentException("...");
    }
    this.end = end;
}

// 상태가 하위 클래스에서만 액세스하도록 의도된 경우 개인 필드를 선언하고 보호된 래퍼 메서드를 통해 액세스를 활성화합니다. 래퍼 메서드를 사용하면 새 값을 설정하기 전에 입력 유효성 검사를 수행할 수있다.
public final class WrappedState {
    // private immutable object
    private String state;

    // wrapper method
    public String getState() {
        return state;
    }

    // wrapper method
    public void setState(final String newState) {
        this.state = requireValidation(newState);
    }

    private static String requireValidation(final String state) {
        if (...) {
            throw new IllegalArgumentException("...");
        }
        return state;
    }
}

//위 분류가 가능한 유형이 있는 필드는 악의적으로 구현된 개체로 설정될 수 있습니다. 항상 public static 필드를 final로 선언하십시오.

public class Files {
    public static final String separator = "/";
    public static final String pathSeparator = ":";
}


