package io.maze.confidentiality;

import static org.junit.Assert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import io.maze.confidentiality.internal.Hex;
import javassist.bytecode.ByteArray;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(Parameterized.class)
@PowerMockIgnore("javax.crypto.*")
public class StreamTest {
    public static final String VECTORS = "../testdata/stream-vectors.txt";

    private static final SecureRandom random = new SecureRandom();

    private Helper.Vector vector;

    public StreamTest(Helper.Vector test) {
        vector = test;
    }

    @Parameters(name = "{0}")
    public static Collection<Helper.Vector> vectors() throws Exception {
        return Helper.loadVectors(VECTORS);
    }

    @Test
    public void decryptStream() throws Exception {
        System.out.println("StreamTest.decryptStream " + vector);

        byte[] key = vector.getBytes("key");
        byte[] input = vector.getBytes("encrypted");
        byte[] want = vector.getBytes("decrypted");
        byte[] test = new byte[want.length];

        ByteArrayInputStream bis = new ByteArrayInputStream(input);
        InputStream stream = Stream.decrypt(bis, key);
        stream.read(test);
        stream.close();

        System.out.println("encrypted:");
        Hex.dump(input);
        System.out.println("decrypted:");
        Hex.dump(test);

        assertThat("message decrypted correctly", test, is(want));
    }   

    @Test
    public void exchange() throws Exception {
        System.out.println("StreamTest.exchange");
        
        byte[] input = new byte[33];
        random.nextBytes(input);
        input[0] = 0x19;

        ByteArrayInputStream bis = new ByteArrayInputStream(input);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(33);
        final byte[] sharedKey = Stream.exchange(bis, bos);
        final byte[] emptyKey = new byte[sharedKey.length];

        System.out.println("shared key:");
        Hex.dump(sharedKey);

        assertThat("sharedKey has 32 bytes", sharedKey.length, is(32));
        assertThat("sharedKey is not zeros", sharedKey, not(is(emptyKey)));
    }
}