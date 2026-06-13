package utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖 {@link UrlRepeat}:去重 / 方法敏感 / 参数值剥离 / 空值校验。
 */
class UrlRepeatTest {

    @Test
    void notSeenBeforeAdd() {
        UrlRepeat r = new UrlRepeat();
        assertFalse(r.check("GET", "http://a.com/"));
    }

    @Test
    void seenAfterAdd() {
        UrlRepeat r = new UrlRepeat();
        r.addMethodAndUrl("GET", "http://a.com/");
        assertTrue(r.check("GET", "http://a.com/"));
    }

    @Test
    void methodSensitive() {
        UrlRepeat r = new UrlRepeat();
        r.addMethodAndUrl("GET", "http://a.com/");
        assertFalse(r.check("POST", "http://a.com/"));
    }

    @Test
    void urlSensitive() {
        UrlRepeat r = new UrlRepeat();
        r.addMethodAndUrl("GET", "http://a.com/x");
        assertFalse(r.check("GET", "http://a.com/y"));
    }

    @Test
    void removeParameterValue() {
        UrlRepeat r = new UrlRepeat();
        assertEquals("http://a.com/x?a=&b=", r.RemoveUrlParameterValue("http://a.com/x?a=1&b=2"));
    }

    @Test
    void noQueryUnchanged() {
        UrlRepeat r = new UrlRepeat();
        assertEquals("http://a.com/x", r.RemoveUrlParameterValue("http://a.com/x"));
    }

    @Test
    void nullMethodThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new UrlRepeat().addMethodAndUrl(null, "http://a.com/"));
    }

    @Test
    void emptyUrlThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new UrlRepeat().addMethodAndUrl("GET", ""));
    }
}
