package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 覆盖 {@link Bfunc#AnalyHost(String, String)}:普通 .com / .com.cn 双后缀 / IP。
 */
class AnalyHostTest {

    @Test
    void comMain() {
        assertEquals("baidu.com", Bfunc.AnalyHost("www.baidu.com", "main"));
    }

    @Test
    void comName() {
        assertEquals("baidu", Bfunc.AnalyHost("www.baidu.com", "name"));
    }

    @Test
    void comCnMain() {
        assertEquals("baidu.com.cn", Bfunc.AnalyHost("www.baidu.com.cn", "main"));
    }

    @Test
    void comCnName() {
        assertEquals("baidu", Bfunc.AnalyHost("www.baidu.com.cn", "name"));
    }

    @Test
    void ipReturnsItselfForMain() {
        assertEquals("1.2.3.4", Bfunc.AnalyHost("1.2.3.4", "main"));
    }

    @Test
    void ipReturnsItselfForName() {
        assertEquals("1.2.3.4", Bfunc.AnalyHost("1.2.3.4", "name"));
    }
}
