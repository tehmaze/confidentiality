package io.maze.confidentiality;

import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Collection;

import org.hamcrest.core.IsNull;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class KeyTest {
    public class KeyTestVector {
        private String name;
        public byte[] raw;
        public Key.Type type;

        KeyTestVector(String name, byte[] raw, Key.Type type) {
            this.raw = raw;
            this.type = type;
            this.name = name;
        }

        public String toString() {
            return name;
        }
    }

    private static KeyTest keyTest = new KeyTest(null);
    private KeyTestVector vector;

    public KeyTest(KeyTestVector test) {
        vector = test;
    }

    @Parameters(name = "{0}")
    public static Collection<KeyTestVector> vectors() throws Exception {
        ArrayList<KeyTestVector> vectors = new ArrayList<KeyTestVector>();
        for (Helper.Vector vector : Helper.loadVectors(AuthenticateTest.VECTORS)) {
            byte[] raw = vector.getBytes("key");
            vectors.add(keyTest.new KeyTestVector((raw.length << 3) + "-bit Authentication Key " + vector.toString(),
                    raw, Key.Type.AUTHENTICATION));
        }
        for (Helper.Vector vector : Helper.loadVectors(MessageTest.VECTORS)) {
            byte[] raw = vector.getBytes("key");
            vectors.add(keyTest.new KeyTestVector((raw.length << 3) + "-bit Message Key " + vector.toString(), raw,
                    Key.Type.MESSAGE));
        }
        return vectors;
    }

    @Test
    public void testKey() throws Exception {
        Key test = new Key(vector.raw, vector.type);
        assertThat("Key can import", test, IsNull.notNullValue());
    }
}