package com.williams.vulnscan.analysis;

/**
 * Lê a tabela de strings e os nomes de método/campo de um DEX.
 * Não descompila bytecode e não reescreve o arquivo.
 */
public final class DexStringTable {
    private static final int HEADER = 0x70;
    private static final int ENDIAN = 0x12345678;
    private static final int MAX_IDS = 250_000;
    private static final int MAX_CHARS = 240;

    public interface Sink {
        void string(String text);

        void method(String name);

        void field(String name);
    }

    private DexStringTable() {
    }

    public static boolean looksLikeDex(byte[] data) {
        return data != null
                && data.length >= HEADER
                && data[0] == 'd'
                && data[1] == 'e'
                && data[2] == 'x'
                && data[3] == '\n'
                && u32(data, 40) == ENDIAN;
    }

    public static void read(byte[] data, Sink sink) {
        if (!looksLikeDex(data)) {
            return;
        }
        int stringCount = u32(data, 56);
        int stringOff = u32(data, 60);
        if (stringCount <= 0 || stringOff < 0) {
            return;
        }
        int count = Math.min(stringCount, MAX_IDS);
        int[] offsets = new int[count];
        int filled = 0;
        for (int i = 0; i < count; i++) {
            int pointer = stringOff + i * 4;
            if (pointer < 0 || pointer + 4 > data.length) {
                break;
            }
            offsets[filled++] = u32(data, pointer);
        }
        if (filled != offsets.length) {
            offsets = java.util.Arrays.copyOf(offsets, filled);
        }
        for (int offset : offsets) {
            if (offset <= 0) {
                continue;
            }
            String value = readMutf8(data, offset, MAX_CHARS);
            if (value != null && !value.isEmpty()) {
                sink.string(value);
            }
        }
        readNames(data, offsets, u32(data, 88), u32(data, 92), true, sink);
        readNames(data, offsets, u32(data, 80), u32(data, 84), false, sink);
    }

    private static void readNames(byte[] data, int[] strings, int count, int offset, boolean method, Sink sink) {
        if (count <= 0 || offset < 0) {
            return;
        }
        int max = Math.min(count, MAX_IDS);
        for (int i = 0; i < max; i++) {
            int base = offset + i * 8;
            if (base < 0 || base + 8 > data.length) {
                return;
            }
            int nameIdx = u32(data, base + 4);
            if (nameIdx < 0 || nameIdx >= strings.length) {
                continue;
            }
            String name = readMutf8(data, strings[nameIdx], 80);
            if (name == null || name.isEmpty()) {
                continue;
            }
            if (method) {
                sink.method(name);
            } else {
                sink.field(name);
            }
        }
    }

    static String readMutf8(byte[] data, int offset, int maxChars) {
        if (offset < 0 || offset >= data.length) {
            return null;
        }
        int[] pos = {offset};
        int utf16Size = readUleb(data, pos);
        if (utf16Size < 0) {
            return null;
        }
        int limit = Math.min(maxChars, Math.max(utf16Size, 0));
        StringBuilder builder = new StringBuilder(Math.min(limit, 64));
        int index = pos[0];
        while (index < data.length && builder.length() < limit) {
            int a = data[index++] & 0xff;
            if (a == 0) {
                break;
            }
            if (a < 0x80) {
                builder.append((char) a);
            } else if ((a & 0xe0) == 0xc0 && index < data.length) {
                int b = data[index++] & 0xff;
                builder.append((char) (((a & 0x1f) << 6) | (b & 0x3f)));
            } else if ((a & 0xf0) == 0xe0 && index + 1 < data.length) {
                int b = data[index++] & 0xff;
                int c = data[index++] & 0xff;
                builder.append((char) (((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f)));
            } else {
                break;
            }
        }
        return builder.toString();
    }

    private static int readUleb(byte[] data, int[] pos) {
        int result = 0;
        int shift = 0;
        int index = pos[0];
        for (int i = 0; i < 5 && index < data.length; i++) {
            int b = data[index++] & 0xff;
            result |= (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                pos[0] = index;
                return result;
            }
            shift += 7;
        }
        pos[0] = index;
        return -1;
    }

    private static int u32(byte[] data, int offset) {
        if (offset < 0 || offset + 4 > data.length) {
            return -1;
        }
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }
}
