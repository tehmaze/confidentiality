package io.maze.confidentiality.internal;

import java.util.Formatter;

/**
 * Helper methods for encode/decode hex strings.
 *
 * @since 1.0.0
 */
public final class Hex {
    private static final String HEX = "0123456789abcdef";

    /** Encodes a byte array to hex. */
    public static String encode(final byte[] bytes) {
        StringBuilder result = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            // convert to unsigned
            int val = b & 0xff;
            result.append(HEX.charAt(val / 16));
            result.append(HEX.charAt(val % 16));
        }
        return result.toString();
    }

    public static String encode(final int value) {
        return encode(toByteArray(value));
    }

    private static byte[] toByteArray(int i) {
        byte[] array = new byte[4];

        array[3] = (byte) (i & 0xFF);
        array[2] = (byte) ((i >> 8) & 0xFF);
        array[1] = (byte) ((i >> 16) & 0xFF);
        array[0] = (byte) ((i >> 24) & 0xFF);

        return array;
    }

    /** Decodes a hex string to a byte array. */
    public static byte[] decode(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Expected a string of even length");
        }
        int size = hex.length() / 2;
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if ((hi == -1) || (lo == -1)) {
                throw new IllegalArgumentException("input is not hexadecimal");
            }
            result[i] = (byte) (16 * hi + lo);
        }
        return result;
    }

    public static void dump(final byte[] bytes) {
        System.out.print(dumpString(bytes, 0, bytes.length));
    }

    public static String dumpString(final byte[] bytes, int offset, int length) {
        StringBuilder result = new StringBuilder();

        byte[] line = new byte[16];
        int lineIndex = 0;

        result.append("0x");
        result.append(encode(offset));

        for (int i = offset; i < offset + length; i++) {
            if (lineIndex == 16) {
                result.append(" | ");

                for (int j = 0; j < 16; j++) {
                    if (line[j] > ' ' && line[j] < '~') {
                        result.append(new String(line, j, 1));
                    } else {
                        result.append(".");
                    }
                }

                result.append("\n0x");
                result.append(encode(i));
                lineIndex = 0;
            }

            byte b = bytes[i];
            result.append(" ");
            result.append(HEX.charAt((b >>> 4) & 0x0F));
            result.append(HEX.charAt(b & 0x0F));

            line[lineIndex++] = b;
        }

        if (lineIndex == 16) {
            result.append(" | ");

        } else {
            int count = (16 - lineIndex) * 3;
            count++;
            for (int i = 0; i < count; i++) {
                result.append(" ");
            }

            result.append("| ");
        }

        for (int i = 0; i < lineIndex; i++) {
            if (line[i] > ' ' && line[i] < '~') {
                result.append(new String(line, i, 1));
            } else {
                result.append(".");
            }
        }

        result.append("\n");
        return result.toString();
    }

    public static String dumper(final byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        Formatter formatter = new Formatter(sb);
        for (int j = 1, l = bytes.length; j < l + 1; j++) {
            if (j % 8 == 1 || j == 0) {
                if (j != 0) {
                    sb.append("\n");
                }
                formatter.format("0%d\t|\t", j / 8);
            }
            formatter.format("%02x", bytes[j - 1]);
            if (j % 4 == 0) {
                sb.append(" ");
            }
        }
        sb.append("\n");
        formatter.close();
        return sb.toString();
    }
}