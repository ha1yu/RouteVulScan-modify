package func;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * 覆盖 {@link vulscan#AnalysisHost(String)}:IP / www 子域 / .com.cn 双后缀 / 多级域名。
 */
class AnalysisHostTest {

    @Test
    void ipReturnsEmpty() {
        assertArrayEquals(new String[]{}, vulscan.AnalysisHost("1.2.3.4"));
    }

    @Test
    void wwwComStripsTldAndSub() {
        assertArrayEquals(new String[]{"baidu"}, vulscan.AnalysisHost("www.baidu.com"));
    }

    @Test
    void plainComStripsTld() {
        assertArrayEquals(new String[]{"baidu"}, vulscan.AnalysisHost("baidu.com"));
    }

    @Test
    void wwwComCnStripsDoubleTld() {
        assertArrayEquals(new String[]{"baidu"}, vulscan.AnalysisHost("www.baidu.com.cn"));
    }

    @Test
    void multiLevelKeepsMiddle() {
        assertArrayEquals(new String[]{"a", "b", "example"}, vulscan.AnalysisHost("a.b.example.com"));
    }
}
