#리소스를 잘못 처리하는 경우, 중복을 최소화하고 처리 문제를 분리

long sum = readFileBuffered(InputStream in -> {
   long current = 0;
   for (;;) {
        int b = in.read();
        if (b == -1) {
            return current;
        }
        current += b;
    }
});

# try-with-resource 구문으로 Release 처리 자동화
public R readFileBuffered(
    InputStreamHandler handler
) throws IOException {
    try (final InputStream in = Files.newInputStream(path)) {
        handler.handle(new BufferedInputStream(in));
    }
}

# 향상된 기능을 지원하지 않는 리소스의 경우 표준 리소스 획득 및 릴르스를 사용해야한다.
public  R locked(Action action) {
    lock.lock();
    try {
        return action.run();
    } finally {
        lock.unlock();
    }
}

# 플러시가 실패하면 코드는 예외를 통해 종료해야한다.
public void writeFile(
    OutputStreamHandler handler
) throws IOException {
    try (final OutputStream rawOut = Files.newOutputStream(path)) {
        final BufferedOutputStream out =
            new BufferedOutputStream(rawOut);
        handler.handle(out);
        out.flush();
    }
}


