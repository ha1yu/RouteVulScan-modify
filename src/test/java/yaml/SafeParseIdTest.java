package yaml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 覆盖 {@link YamlUtil#safeParseId(Object)}:统一 id 在 YAML(Integer)、内存 LogEntry(String)、
 * UI 输入(任意字符串)间的类型转换,避免 ClassCastException / NumberFormatException。
 */
class SafeParseIdTest {

    @Test
    void integerId() {
        assertEquals(8, YamlUtil.safeParseId(8));
    }

    @Test
    void stringNumericId() {
        assertEquals(8, YamlUtil.safeParseId("8"));
    }

    @Test
    void stringNumericWithWhitespace() {
        assertEquals(42, YamlUtil.safeParseId("  42  "));
    }

    @Test
    void nonNumericStringReturnsNegativeOne() {
        assertEquals(-1, YamlUtil.safeParseId("abc"));
    }

    @Test
    void nullReturnsNegativeOne() {
        assertEquals(-1, YamlUtil.safeParseId(null));
    }

    @Test
    void emptyStringReturnsNegativeOne() {
        assertEquals(-1, YamlUtil.safeParseId(""));
    }
}
