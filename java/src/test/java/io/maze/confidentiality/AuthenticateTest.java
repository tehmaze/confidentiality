package io.maze.confidentiality;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class AuthenticateTest {
    public static final String VECTORS = "../testdata/authentication-vectors.txt";


    private Helper.Vector vector;
    public AuthenticateTest(Helper.Vector test) {
        vector = test;
    }

    @Parameters(name = "{0}")
    public static Collection<Helper.Vector> vectors() throws Exception {
        return Helper.loadVectors(VECTORS);
    }

    /**
     * TODO(maze): unbreak this test
     */
    /*
    @Test
    public void testSignature() throws Exception {
        final byte[] want = vector.getBytes("signature");
        final byte[] test = Authenticate.signature(vector.getString("message"), vector.getBytes("key"));
        assertArrayEquals("signature " + Helper.bytesToHex(test) + " = " + Helper.bytesToHex(want),want, test);
    }
    */

    @Test
    public void testVerify() throws Exception {
        final byte[] test = Helper.combine(vector.getBytes("message"), vector.getBytes("signature"));
        final byte[] key = vector.getBytes("key");
        assertTrue("signature verifies", Authenticate.verify(test, key));
    }
}