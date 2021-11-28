// password type을 사용함으로써 비밀번호가 사용자 화면에서 가려지게 함
// 자동완성을 비활성화하여 내 비밀번호를 지켜낼 수 있음
<input type="password" name="passwd" autocomplete="off" />

// POST로 form 데이터를 전송하며, Token도 같이 보낸다.
<form method="post" action="https://somedomain.com/user/signin" autocomplete="off">
    <input type="hidden" name="csrf" value="CSRF-TOKEN" />

    <label>Username <input type="text" name="username" /></label>
    <label>Password <input type="password" name="password" /></label>

    <input type="submit" value="Submit" />
</form>

// ID, PASSWD중 하나만 틀렸다고 해도, 어느 부분이 잘못되었는지 알리면 안됨
// 아이디나 패스워드 중 하나가 잘못되었다고 해야한다.
<form method="post" action="https://somedomain.com/user/signin" autocomplete="off">
    <input type="hidden" name="csrf" value="CSRF-TOKEN" />

    <div class="error">
        <p>Invalid username and/or password</p>
    </div>

    <label>Username <input type="text" name="username" /></label>
    <label>Password <input type="password" name="password" /></label>

    <input type="submit" value="Submit" />
</form>
