// 기본 역직렬화이며 ObjectInputStream.defaultReadObject비일시적 필드에 임의의 개체를 할당할 수 있으며 반드시 반환되지는 않습니다. ObjectInputStream.readFields필드에 할당하기 전에 복사를 삽입하는 대신 사용하십시오 . 또는 가능하다면 민감한 클래스를 직렬화하지 마십시오.
public final class ByteString implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] data;
    public ByteString(byte[] data) {
        this.data = data.clone(); // Make copy before assignment.
    }
    private void readObject(
        java.io.ObjectInputStream in
    ) throws java.io.IOException, ClassNotFoundException {
        java.io.ObjectInputStreadm.GetField fields =
            in.readFields();
        this.data = ((byte[])fields.get("data")).clone();
    }
    ...
}

// readObject 구현의 내부 필드에 할당하기 전에 역직렬화된 변경 가능한 개체의 복사본을 만듭니다 . 이는 역직렬화된 컨테이너 개체 내부의 변경 가능한 개체에 대한 참조를 공격자에게 제공하도록 특수하게 조작된 적대적인 코드 역직렬화 바이트 스트림을 방어합니다.

public final class Nonnegative implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private int value;
    public Nonnegative(int value) {
        // Make check before assignment.
        this.data = nonnegative(value);
    }
    private static int nonnegative(int value) {
        if (value < 0) {
            throw new IllegalArgumentException(value +
                                               " is negative");
        }
        return value;
    }
    private void readObject(
        java.io.ObjectInputStream in
    ) throws java.io.IOException, ClassNotFoundException {
        java.io.ObjectInputStreadm.GetField fields =
            in.readFields();
        this.value = nonnegative(field.get(value, 0));
    }
    ...
}

//를 우회하는 것을 방지합니다 . 특히 직렬화 가능한 클래스 SecurityManager가 생성자에서 검사를 시행하는 경우 readObject또는 readObjectNoData메서드 구현 에서 동일한 검사를 시행합니다 . 그렇지 않으면 역직렬화를 통한 검사 없이 클래스의 인스턴스를 만들 수 있습니다.

public final class SensitiveClass implements java.io.Serializable {
    public SensitiveClass() {
        // permission needed to instantiate SensitiveClass
        securityManagerCheck();

        // regular logic follows
    }

    // implement readObject to enforce checks
    //   during deserialization
    private void readObject(java.io.ObjectInputStream in) {
        // duplicate check from constructor
        securityManagerCheck();

        // regular logic follows
    }
}

//직렬화 가능 클래스를 통해 호출자가 내부 상태를 검색할 수 있고 검색 SecurityManager이 민감한 데이터의 공개를 방지하기 위한 검사로 보호 되는 경우 writeObject 메서드 구현 에서 동일한 검사를 시행합니다 . 그렇지 않으면 공격자가 개체를 직렬화하여 검사를 우회하고 직렬화된 바이트 스트림을 읽는 것만으로 내부 상태에 액세스할 수 있습니다.

public final class SecureValue implements java.io.Serializable {
    // sensitive internal state
    private String value;

    // public method to allow callers to retrieve internal state

    public String getValue() {
        // permission needed to get value
        securityManagerCheck();

        return value;
    }


    // implement writeObject to enforce checks
    //  during serialization
    private void writeObject(java.io.ObjectOutputStream out) {
        // duplicate check from getValue()
        securityManagerCheck();
        out.writeObject(value);
    }
}
