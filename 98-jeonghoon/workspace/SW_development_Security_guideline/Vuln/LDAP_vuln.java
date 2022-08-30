private void searchRecord(String userSN, String userPassword) throws
NamingException {
Hashtable<String, String> env = new Hashtable<String, String>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
try {
DirContext dctx = new InitialDirContext(env);
SearchControls sc = new SearchControls();
String[] attributeFilter = { "cn", "mail" };
sc.setReturningAttributes(attributeFilter);
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";
//userSN과 userPassword 값에 LDAP필터를 조작할 수 있는 공격 문자열에 대한 검증이 없어
안전하지 않다.
String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
NamingEnumeration<?> results = dctx.search(base, filter, sc);
while (results.hasMore()) {
SearchResult sr = (SearchResult) results.next();
Attributes attrs = sr.getAttributes();
Attribute attr = attrs.get("cn");
.....
}
dctx.close();
} catch (NamingException e) { … }
}
