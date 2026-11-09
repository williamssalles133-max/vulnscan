package com.williams.vulnscan.analysis;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** DEX mínimo para testes: tabela de strings, um método e um campo. */
final class TinyDex {
    private TinyDex() {
    }

    static byte[] build(List<String> strings, int methodNameIndex, int fieldNameIndex) {
        int stringCount = strings.size();
        int methodCount = methodNameIndex >= 0 ? 1 : 0;
        int fieldCount = fieldNameIndex >= 0 ? 1 : 0;
        int stringIdsOff = 0x70;
        int fieldIdsOff = stringIdsOff + stringCount * 4;
        int methodIdsOff = fieldIdsOff + fieldCount * 8;
        int dataOff = methodIdsOff + methodCount * 8;

        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int[] offsets = new int[stringCount];
        for (int i = 0; i < stringCount; i++) {
            offsets[i] = dataOff + data.size();
            writeString(data, strings.get(i));
        }

        int fileSize = dataOff + data.size();
        ByteBuffer header = ByteBuffer.allocate(dataOff).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'d', 'e', 'x', '\n', '0', '3', '5', 0});
        header.putInt(0);
        header.put(new byte[20]);
        header.putInt(fileSize);
        header.putInt(0x70);
        header.putInt(0x12345678);
        header.putInt(0);
        header.putInt(0);
        header.putInt(0);
        header.putInt(stringCount);
        header.putInt(stringIdsOff);
        header.putInt(0);
        header.putInt(0);
        header.putInt(0);
        header.putInt(0);
        header.putInt(fieldCount);
        header.putInt(fieldCount == 0 ? 0 : fieldIdsOff);
        header.putInt(methodCount);
        header.putInt(methodCount == 0 ? 0 : methodIdsOff);
        header.putInt(0);
        header.putInt(0);
        header.putInt(data.size());
        header.putInt(dataOff);
        for (int offset : offsets) {
            header.putInt(offset);
        }
        if (fieldCount == 1) {
            header.putShort((short) 0);
            header.putShort((short) 0);
            header.putInt(fieldNameIndex);
        }
        if (methodCount == 1) {
            header.putShort((short) 0);
            header.putShort((short) 0);
            header.putInt(methodNameIndex);
        }
        byte[] head = header.array();
        byte[] body = data.toByteArray();
        byte[] all = new byte[head.length + body.length];
        System.arraycopy(head, 0, all, 0, head.length);
        System.arraycopy(body, 0, all, head.length, body.length);
        return all;
    }

    private static void writeString(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeUleb(out, value.length());
        out.write(bytes, 0, bytes.length);
        out.write(0);
    }

    private static void writeUleb(ByteArrayOutputStream out, int value) {
        int remaining = value;
        while (true) {
            int piece = remaining & 0x7f;
            remaining >>>= 7;
            if (remaining != 0) {
                out.write(piece | 0x80);
            } else {
                out.write(piece);
                return;
            }
        }
    }
}
