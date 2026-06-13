package burp;

import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖 {@link Bfunc#StatusCodeProc(String)}:单值 / 范围 / 逗号列表 / 混合。
 */
class StatusCodeProcTest {

    @Test
    void singleCode() {
        Collection<Integer> r = Bfunc.StatusCodeProc("200");
        assertEquals(1, r.size());
        assertTrue(r.contains(200));
    }

    @Test
    void range() {
        Collection<Integer> r = Bfunc.StatusCodeProc("200-202");
        assertEquals(3, r.size());
        assertTrue(r.contains(200));
        assertTrue(r.contains(201));
        assertTrue(r.contains(202));
    }

    @Test
    void rangeSpansHundred() {
        assertEquals(100, Bfunc.StatusCodeProc("500-599").size());
    }

    @Test
    void commaList() {
        Collection<Integer> r = Bfunc.StatusCodeProc("200,404");
        assertEquals(2, r.size());
        assertTrue(r.contains(200));
        assertTrue(r.contains(404));
    }

    @Test
    void mixedRangeAndSingle() {
        Collection<Integer> r = Bfunc.StatusCodeProc("200-201,302");
        assertEquals(3, r.size());
        assertTrue(r.contains(200));
        assertTrue(r.contains(201));
        assertTrue(r.contains(302));
    }
}
