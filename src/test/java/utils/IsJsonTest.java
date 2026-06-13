package utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖 {@link CustomHelpers#isJson(String)}。
 */
class IsJsonTest {

    @Test
    void jsonObject() {
        assertTrue(CustomHelpers.isJson("{\"a\":1}"));
    }

    @Test
    void jsonArray() {
        assertTrue(CustomHelpers.isJson("[1,2]"));
    }

    @Test
    void trimmedWhitespace() {
        assertTrue(CustomHelpers.isJson("   {\"a\":1}   "));
    }

    @Test
    void emptyBraces() {
        assertTrue(CustomHelpers.isJson("{}"));
    }

    @Test
    void plainString() {
        assertFalse(CustomHelpers.isJson("hello"));
    }

    @Test
    void nullString() {
        assertFalse(CustomHelpers.isJson(null));
    }

    @Test
    void emptyString() {
        assertFalse(CustomHelpers.isJson(""));
    }

    @Test
    void openBracketOnly() {
        assertFalse(CustomHelpers.isJson("{"));
    }
}
