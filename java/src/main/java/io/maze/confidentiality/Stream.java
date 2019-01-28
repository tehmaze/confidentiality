package io.maze.confidentiality;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.omg.CORBA.DynAnyPackage.Invalid;

import io.maze.confidentiality.internal.X25519;

public class Stream {
    static private byte ECC_X25519 = 0x19;
    static private int IV_SIZE = 16;
    static private int PBKDF2_ITER = 4096;
    static private int PBKDF2_SIZE = 32;
    static private Stream instance = new Stream();
    static private SecureRandom random = new SecureRandom();

    static public String ALGORITHM = "PBKDF2WithHmacSHA256";

    static public byte[] exchange(InputStream is, OutputStream os) throws IOException, InvalidKeyException {
        // Generate ephemeral X25519 key.
        final byte[] localSecretKey = X25519.generatePrivateKey();
        final byte[] localPublicKey = X25519.publicFromPrivate(localSecretKey);

        // Write it to the stream.
        final byte[] wireFormat = new byte[localPublicKey.length + 1];
        wireFormat[0] = ECC_X25519;
        System.arraycopy(localPublicKey, 0, wireFormat, 1, localPublicKey.length);
        os.write(wireFormat);

        // Read peers public key.
        for (int i = 0, l = wireFormat.length; i < l;) {
            i += is.read(wireFormat, i, l - i);
        }
        if (wireFormat[0] != ECC_X25519) {
            throw new InvalidKeyException("Peer sent an unknown key format");
        }
        final byte[] peersPublicKey = Arrays.copyOfRange(wireFormat, 1, localPublicKey.length + 1);

        // Compute shared key.
        final byte[] sharedKey = X25519.computeSharedSecret(localSecretKey, peersPublicKey);

        // Derive the output from the shared key for our final key.
        Stream.PRF prf = instance.new MacBasedPRF("HmacSHA256");
        prf.init(sharedKey);
        byte[] salt = new byte[0];
        return PBKDF2(prf, salt, PBKDF2_ITER, PBKDF2_SIZE);
    }

    static public OutputStream encrypt(OutputStream stream, SecretKeySpec aes) throws IOException, InvalidKeyException {
        try {
            byte[] nonce = new byte[Message.NONCE_SIZE];
            random.nextBytes(nonce);
            stream.write(nonce);

            GCMParameterSpec gcm = new GCMParameterSpec(Message.TAG_BITS, nonce);
            Cipher aesgcm = Cipher.getInstance("AES/GCM/NoPadding");
            aesgcm.init(Cipher.ENCRYPT_MODE, aes, gcm);

            byte[] iv = new byte[IV_SIZE];
            random.nextBytes(iv);
            stream.write(aesgcm.doFinal(iv));

            IvParameterSpec ctr = new IvParameterSpec(iv);
            Cipher aesctr = Cipher.getInstance("AES/CTR/NoPadding");
            aesctr.init(Cipher.ENCRYPT_MODE, aes, ctr);

            return new CipherOutputStream(stream, aesctr);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException error) {
            throw new RuntimeException(error);
        }
    }

    static public OutputStream encrypt(OutputStream stream, byte[] aesBytes) throws IOException, InvalidKeyException {
        return encrypt(stream, new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }

    static public InputStream decrypt(InputStream stream, SecretKeySpec aes) throws IOException, InvalidKeyException {
        try {
            byte[] nonce = new byte[Message.NONCE_SIZE];
            stream.read(nonce);

            GCMParameterSpec gcm = new GCMParameterSpec(Message.TAG_BITS, nonce);
            Cipher aesgcm = Cipher.getInstance("AES/GCM/NoPadding");
            aesgcm.init(Cipher.DECRYPT_MODE, aes, gcm);

            byte[] encryptedIVAndTag = new byte[IV_SIZE + (Message.TAG_BITS >> 3)];
            stream.read(encryptedIVAndTag);
            byte[] iv = aesgcm.doFinal(encryptedIVAndTag);
            
            IvParameterSpec ctr = new IvParameterSpec(iv);
            Cipher aesctr = Cipher.getInstance("AES/CTR/NoPadding");
            aesctr.init(Cipher.DECRYPT_MODE, aes, ctr);

            return new CipherInputStream(stream, aesctr);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException error) {
            throw new RuntimeException(error);
        }
    }

    static public InputStream decrypt(InputStream stream, byte[] aesBytes) throws IOException, InvalidKeyException {
        return decrypt(stream, new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }

    private interface PRF {
        /**
         * Initialize this instance with the user-supplied password.
         * 
         * @param P The password supplied as array of bytes. It is the caller's task to
         *          convert String passwords to bytes as appropriate.
         */
        public void init(byte[] P);

        /**
         * Pseudo Random Function
         * 
         * @param M Input data/message etc. Together with any data supplied during
         *          initilization.
         * @return Random bytes of hLen length.
         */
        public byte[] doFinal(byte[] M);

        /**
         * Query block size of underlying algorithm/mechanism.
         * 
         * @return block size
         */
        public int getHLen();
    }

    private class MacBasedPRF implements PRF {
        protected Mac mac;
        protected int hLen;
        protected String macAlgorithm;

        /**
         * Create Mac-based Pseudo Random Function.
         * 
         * @param macAlgorithm Mac algorithm to use, i.e. HMacSHA1 or HMacMD5.
         */
        public MacBasedPRF(String macAlgorithm) {
            this.macAlgorithm = macAlgorithm;
            try {
                mac = Mac.getInstance(macAlgorithm);
                hLen = mac.getMacLength();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        /*
         * public MacBasedPRF(String macAlgorithm, String provider) { this.macAlgorithm
         * = macAlgorithm; try { mac = Mac.getInstance(macAlgorithm, provider); hLen =
         * mac.getMacLength(); } catch (NoSuchAlgorithmException e) { throw new
         * RuntimeException(e); } catch (NoSuchProviderException e) { throw new
         * RuntimeException(e); } }
         */

        public byte[] doFinal(byte[] M) {
            byte[] r = mac.doFinal(M);
            return r;
        }

        public int getHLen() {
            return hLen;
        }

        public void init(byte[] P) {
            try {
                mac.init(new SecretKeySpec(P, macAlgorithm));
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Core Password Based Key Derivation Function 2.
     * 
     * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2</a>
     * @param prf   Pseudo Random Function (i.e. HmacSHA1)
     * @param S     Salt as array of bytes. <code>null</code> means no salt.
     * @param c     Iteration count (see RFC 2898 4.2)
     * @param dkLen desired length of derived key.
     * @return internal byte array
     */
    static protected byte[] PBKDF2(PRF prf, byte[] S, int c, int dkLen) {
        if (S == null) {
            S = new byte[0];
        }
        int hLen = prf.getHLen();
        int l = ceil(dkLen, hLen);
        int r = dkLen - (l - 1) * hLen;
        byte T[] = new byte[l * hLen];
        int ti_offset = 0;
        for (int i = 1; i <= l; i++) {
            _F(T, ti_offset, prf, S, c, i);
            ti_offset += hLen;
        }
        if (r < hLen) {
            // Incomplete last block
            byte DK[] = new byte[dkLen];
            System.arraycopy(T, 0, DK, 0, dkLen);
            return DK;
        }
        return T;
    }

    /**
     * Function F.
     * 
     * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2 Step 3.</a>
     * @param dest       Destination byte buffer
     * @param offset     Offset into destination byte buffer
     * @param prf        Pseudo Random Function
     * @param S          Salt as array of bytes
     * @param c          Iteration count
     * @param blockIndex
     */
    static protected void _F(byte[] dest, int offset, PRF prf, byte[] S, int c, int blockIndex) {
        int hLen = prf.getHLen();
        byte U_r[] = new byte[hLen];

        // U0 = S || INT (i);
        byte U_i[] = new byte[S.length + 4];
        System.arraycopy(S, 0, U_i, 0, S.length);
        INT(U_i, S.length, blockIndex);

        for (int i = 0; i < c; i++) {
            U_i = prf.doFinal(U_i);
            xor(U_r, U_i);
        }
        System.arraycopy(U_r, 0, dest, offset, hLen);
    }

    /**
     * Block-Xor. Xor source bytes into destination byte buffer. Destination buffer
     * must be same length or less than source buffer.
     * 
     * @param dest
     * @param src
     */
    static protected void xor(byte[] dest, byte[] src) {
        for (int i = 0; i < dest.length; i++) {
            dest[i] ^= src[i];
        }
    }

    /**
     * Four-octet encoding of the integer i, most significant octet first.
     * 
     * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2 Step 3.</a>
     * @param dest
     * @param offset
     * @param i
     */
    static protected void INT(byte[] dest, int offset, int i) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    }

    /**
     * Integer division with ceiling function.
     * 
     * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2 Step 2.</a>
     * @param a
     * @param b
     * @return ceil(a/b)
     */
    static protected int ceil(int a, int b) {
        int m = 0;
        if (a % b > 0) {
            m = 1;
        }
        return a / b + m;
    }
}