// pacakage.access 보안 속성을 추가하여 구현 코드를 숨긴다.
private static final String PACKAGE_ACCESS_KEY = "package.access";
static {
    String packageAccess = java.security.Security.getProperty(
        PACKAGE_ACCESS_KEY
    );
    java.security.Security.setProperty(
        PACKAGE_ACCESS_KEY,
        (
            (packageAccess == null ||
             packageAccess.trim().isEmpty()) ?
            "" :
            (packageAccess + ",")
        ) +
        "xx.example.product.implementation."
    );
}
