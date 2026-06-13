package func;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖 {@link vulscan#AnalysisHeaders(java.util.List)};含修复点(缺冒号)回归。
 */
class AnalysisHeadersTest {

    @Test
    void normalParse() {
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Host: www.baidu.com", "User-Agent: curl"));
        HashMap<String, String> m = vulscan.AnalysisHeaders(headers);
        assertEquals("www.baidu.com", m.get("Host"));
        assertEquals("curl", m.get("User-Agent"));
    }

    @Test
    void keyNotLowercased() {
        // 与 ProceHead 不同:AnalysisHeaders 的 key 保持原大小写
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "X-Test: v"));
        HashMap<String, String> m = vulscan.AnalysisHeaders(headers);
        assertTrue(m.containsKey("X-Test"));
    }

    @Test
    void missingColonSkipped() {
        // 修复点:原实现 substring(0,-1) 崩溃,修复后跳过非法行
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "badLine", "Server: nginx"));
        HashMap<String, String> m = vulscan.AnalysisHeaders(headers);
        assertEquals("nginx", m.get("Server"));
    }

    @Test
    void firstLineRemovedSideEffect() {
        List<String> headers = new ArrayList<>(Arrays.asList("GET / HTTP/1.1", "Server: nginx"));
        vulscan.AnalysisHeaders(headers);
        assertEquals(1, headers.size());
    }
}
