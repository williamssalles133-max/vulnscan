package com.williams.vulnscan.analysis;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DexStringTableTest {
    @Test
    public void readsStringPoolAndMemberNames() {
        List<String> pool = Arrays.asList(
                "https://api.example.com/v1/login",
                "AES/ECB/PKCS5Padding",
                "addJavascriptInterface",
                "apiKey");
        byte[] dex = TinyDex.build(pool, 2, 3);
        assertTrue(DexStringTable.looksLikeDex(dex));

        List<String> strings = new ArrayList<>();
        List<String> methods = new ArrayList<>();
        List<String> fields = new ArrayList<>();
        DexStringTable.read(dex, new DexStringTable.Sink() {
            @Override
            public void string(String text) {
                strings.add(text);
            }

            @Override
            public void method(String name) {
                methods.add(name);
            }

            @Override
            public void field(String name) {
                fields.add(name);
            }
        });

        assertEquals(pool, strings);
        assertEquals(CollectionsOf.one("addJavascriptInterface"), methods);
        assertEquals(CollectionsOf.one("apiKey"), fields);
    }

    @Test
    public void ignoresNonDexBytes() {
        byte[] data = "not a dex, just http://example.com".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        assertTrue(!DexStringTable.looksLikeDex(data));
        List<String> strings = new ArrayList<>();
        DexStringTable.read(data, new DexStringTable.Sink() {
            @Override
            public void string(String text) {
                strings.add(text);
            }

            @Override
            public void method(String name) {
                strings.add(name);
            }

            @Override
            public void field(String name) {
                strings.add(name);
            }
        });
        assertTrue(strings.isEmpty());
    }

    private static final class CollectionsOf {
        static List<String> one(String value) {
            return java.util.Collections.singletonList(value);
        }
    }
}
