package io.maze.confidentiality;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import io.maze.confidentiality.internal.Hex;

public class Helper {
    public class Vector {
        Vector(String line, String[] header) {
            String[] values = line.split(":");
            for (int i = 0, l = values.length; i < l; i++) {
                vector.put(header[i], values[i]);
            }
        }

        public byte[] getBytes(String key) {
            return Hex.decode(vector.get(key));
        }

        public String getString(String key) {
            return vector.get(key);
        }

        public String toString() {
            return getString("name");
        }

        public HashMap<String, String> vector = new HashMap<>();
    }

    public static String bytesToHex(byte []bytes) {
        StringBuilder output = new StringBuilder(bytes.length << 1);
        for (byte b : bytes) {
            output.append(String.format("%02x", b));
        }
        return output.toString();
    }

    public static byte[] combine(byte[]... args) {
        int total = 0;
        for (int i = 0, l = args.length; i < l; i++) {
            total += args[i].length;
        }

        final byte[] output = new byte[total];
        int offset = 0;
        for (int i = 0, l = args.length; i < l; i++) {
            System.arraycopy(args[i], 0, output, offset, args[i].length);
            offset += args[i].length;
        }

        return output;
    }

    public static ArrayList<Vector> loadVectors(String name)
            throws FileNotFoundException, IOException, IllegalArgumentException {
        ArrayList<Vector> output = new ArrayList<Vector>();
        try (BufferedReader reader = new BufferedReader(new FileReader(name))) {
            int lineno = 1;
            String line;
            String[] header = null;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.length() == 0) {
                    continue;
                } else if (line.startsWith("# cols=")) {
                    header = line.substring("# cols=".length()).split(":");
                    continue;
                } else if (line.startsWith("#")) {
                    continue;
                } else if (header == null) {
                    throw new IllegalArgumentException(name + "[" + lineno + "]: vector found, but no header present");
                }

                output.add(helper.new Vector(line, header));
            }
        }
        return output;
    }
    
    private static final Helper helper = new Helper();
}