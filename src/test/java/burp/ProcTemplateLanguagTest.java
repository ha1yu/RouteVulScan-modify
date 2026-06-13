package burp;

import func.vulscan;
import org.junit.jupiter.api.Test;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 覆盖 {@link Bfunc#ProcTemplateLanguag(String, IHttpRequestResponse, vulscan, Boolean)} 的模板替换核心。
 * 用 {@link Unsafe#allocateInstance} 构造不触发构造器副作用的 vulscan/BurpExtender 裸实例(仅暴露 public 字段
 * {@code vul.burp.help}),用 {@link Proxy} 为 Burp 接口提供最小桩,不引入 Mockito。
 */
class ProcTemplateLanguagTest {

    private static Unsafe getUnsafe() throws Exception {
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (Unsafe) f.get(null);
    }

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> iface, Map<String, Object> returns) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("toString")) return iface.getSimpleName() + "#stub";
                    if (name.equals("hashCode")) return System.identityHashCode(proxy);
                    if (name.equals("equals")) return proxy == args[0];
                    Class<?> rt = method.getReturnType();
                    Object v = returns.get(name);
                    if (rt == short.class) return v == null ? (short) 0 : ((Number) v).shortValue();
                    if (rt == int.class) return v == null ? 0 : ((Number) v).intValue();
                    if (rt == long.class) return v == null ? 0L : ((Number) v).longValue();
                    if (rt == byte.class) return v == null ? (byte) 0 : ((Number) v).byteValue();
                    if (rt == float.class) return v == null ? 0f : ((Number) v).floatValue();
                    if (rt == double.class) return v == null ? 0d : ((Number) v).doubleValue();
                    if (rt == boolean.class) return v != null && (Boolean) v;
                    if (rt == char.class) return v == null ? (char) 0 : (Character) v;
                    return v;
                });
    }

    private static vulscan newVulscanWithHelpers(IExtensionHelpers helpers) throws Exception {
        Unsafe u = getUnsafe();
        BurpExtender burp = (BurpExtender) u.allocateInstance(BurpExtender.class);
        burp.help = helpers;
        vulscan vul = (vulscan) u.allocateInstance(vulscan.class);
        vul.burp = burp;
        return vul;
    }

    private static IExtensionHelpers buildHelpers(Map<String, Object> reqReturns, Map<String, Object> respReturns) {
        IRequestInfo request = stub(IRequestInfo.class, reqReturns);
        Map<String, Object> h = new HashMap<>();
        h.put("analyzeRequest", request);
        if (respReturns != null) {
            h.put("analyzeResponse", stub(IResponseInfo.class, respReturns));
        }
        return stub(IExtensionHelpers.class, h);
    }

    private static IHttpRequestResponse emptyRequestResponse() {
        return stub(IHttpRequestResponse.class, new HashMap<>());
    }

    @Test
    void noTemplateReturnedAsIs() throws Exception {
        vulscan vul = newVulscanWithHelpers(buildHelpers(new HashMap<>(), null));
        assertEquals("/actuator/env", Bfunc.ProcTemplateLanguag("/actuator/env", emptyRequestResponse(), vul, false));
    }

    @Test
    void requestMethod() throws Exception {
        Map<String, Object> req = new HashMap<>();
        req.put("getMethod", "GET");
        vulscan vul = newVulscanWithHelpers(buildHelpers(req, null));
        assertEquals("/GETsecret", Bfunc.ProcTemplateLanguag("/{{request.method}}secret", emptyRequestResponse(), vul, false));
    }

    @Test
    void requestPath() throws Exception {
        URL url = new URL("https://www.baidu.com/aaa/bbb");
        Map<String, Object> req = new HashMap<>();
        req.put("getUrl", url);
        vulscan vul = newVulscanWithHelpers(buildHelpers(req, null));
        assertEquals("aaa/bbb", Bfunc.ProcTemplateLanguag("{{request.path}}", emptyRequestResponse(), vul, false));
    }

    @Test
    void requestHeadCookie() throws Exception {
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Cookie: session=abc"));
        Map<String, Object> req = new HashMap<>();
        req.put("getHeaders", headers);
        vulscan vul = newVulscanWithHelpers(buildHelpers(req, null));
        assertEquals("/session=abc", Bfunc.ProcTemplateLanguag("/{{request.head.cookie}}", emptyRequestResponse(), vul, false));
    }

    @Test
    void requestHeadHostMain() throws Exception {
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Host: www.baidu.com"));
        Map<String, Object> req = new HashMap<>();
        req.put("getHeaders", headers);
        vulscan vul = newVulscanWithHelpers(buildHelpers(req, null));
        assertEquals("baidu.com", Bfunc.ProcTemplateLanguag("{{request.head.host.main}}", emptyRequestResponse(), vul, false));
    }

    @Test
    void responseStatus() throws Exception {
        Map<String, Object> resp = new HashMap<>();
        resp.put("getStatusCode", 200);
        vulscan vul = newVulscanWithHelpers(buildHelpers(new HashMap<>(), resp));
        Map<String, Object> rr = new HashMap<>();
        rr.put("getResponse", "HTTP/1.1 200 OK\r\n\r\n".getBytes());
        IHttpRequestResponse request = stub(IHttpRequestResponse.class, rr);
        assertEquals("/200", Bfunc.ProcTemplateLanguag("/{{response.status}}", request, vul, false));
    }

    @Test
    void escapeQuotesValue() throws Exception {
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Cookie: test.value"));
        Map<String, Object> req = new HashMap<>();
        req.put("getHeaders", headers);
        vulscan vul = newVulscanWithHelpers(buildHelpers(req, null));
        // escape=true 时替换值用 Pattern.quote 转义,作为正则安全使用
        String expected = "re/" + Pattern.quote("test.value");
        assertEquals(expected, Bfunc.ProcTemplateLanguag("re/{{request.head.cookie}}", emptyRequestResponse(), vul, true));
    }
}
