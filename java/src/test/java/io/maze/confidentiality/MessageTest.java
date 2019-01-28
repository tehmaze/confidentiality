package io.maze.confidentiality;

import static org.junit.Assert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import io.maze.confidentiality.internal.Hex;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(Parameterized.class)
@PowerMockIgnore("javax.crypto.*")
public class MessageTest {
    public static final String VECTORS = "../testdata/message-vectors.txt";

    private Helper.Vector vector;

    public MessageTest(Helper.Vector test) {
        vector = test;
    }

    @Parameters(name = "{0}")
    public static Collection<Helper.Vector> vectors() throws Exception {
        return Helper.loadVectors(VECTORS);
    }

    @Test
    public void encryptingAMessage() throws Exception {
        System.out.println("MessageTest.encrypting a message: " + vector);

        final byte[] want = Helper.combine(vector.getBytes("nonce"), vector.getBytes("ciphertext"));
        final byte[] test = Message.encrypt(vector.getBytes("plaintext"), vector.getBytes("key"));

        System.out.println("decrypted:");
        Hex.dump(vector.getBytes("plaintext"));
        System.out.println("encrypted:");
        Hex.dump(test);

        assertThat("encrypt returns byte[]", test instanceof byte[], is(true));
        assertThat("encrypted length is " + want.length, test.length, is(want.length));
    }

    @Test
    public void decryptingAMessage() throws Exception {
        System.out.println("MessageTest.decrypting a message: " + vector);

        final byte[] want = vector.getBytes("plaintext");
        final byte[] test = Message.decrypt(Helper.combine(vector.getBytes("nonce"), vector.getBytes("ciphertext")),
                vector.getBytes("key"));

        System.out.println("encrypted:");
        Hex.dump(Helper.combine(vector.getBytes("nonce"), vector.getBytes("ciphertext")));
        System.out.println("decrypted:");
        Hex.dump(test);      

        assertThat("decrypt retusn byte[]", test instanceof byte[], is(true));
        assertThat("decryption succeeds", test, equalTo(want));
    }
}