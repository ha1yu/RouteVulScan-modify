package burp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * 覆盖 {@link Bfunc#ProceHead(java.util.List)};含修复点(无空格 / 缺冒号)回归。
 */
class ProceHeadTest {

    @Test
    void normalWithSpace() {
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Host: www.baidu.com", "Cookie: x=1"));
        Map<String, String> m = Bfunc.ProceHead(heads);
        assertEquals("www.baidu.com", m.get("host"));
        assertEquals("x=1", m.get("cookie"));
    }

    @Test
    void noSpaceAfterColon() {
        // 修复点:原实现 substring(index+2) 会吃掉首字符,修复后按冒号切分 + trim
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Host:www.baidu.com"));
        Map<String, String> m = Bfunc.ProceHead(heads);
        assertEquals("www.baidu.com", m.get("host"));
    }

    @Test
    void valueContainingColon() {
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "X-Forwarded-For: 1.2.3.4:5678"));
        Map<String, String> m = Bfunc.ProceHead(heads);
        assertEquals("1.2.3.4:5678", m.get("x-forwarded-for"));
    }

    @Test
    void missingColonSkipped() {
        // 修复点:原实现 indexOf=-1 导致 substring(0,-1) 崩溃,修复后跳过该行
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "garbageLine", "Server: nginx"));
        Map<String, String> m = Bfunc.ProceHead(heads);
        assertEquals("nginx", m.get("server"));
        assertFalse(m.containsKey("garbageline"));
    }

    @Test
    void valueTrimmed() {
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Server:    nginx   "));
        Map<String, String> m = Bfunc.ProceHead(heads);
        assertEquals("nginx", m.get("server"));
    }

    @Test
    void firstLineRemovedSideEffect() {
        // 副作用:首行(请求行)被移除
        List<String> heads = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Server: nginx"));
        Bfunc.ProceHead(heads);
        assertEquals(1, heads.size());
        assertEquals("Server: nginx", heads.get(0));
    }
}
