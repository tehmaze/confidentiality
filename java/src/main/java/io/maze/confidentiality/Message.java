package io.maze.confidentiality;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Message {
    public static String ALGORITHM = "AES";
    public static String CIPHER = "AES/GCM/NoPadding";
    public static int NONCE_SIZE = 12;
    public static int TAG_BITS = 128;
    public static int OVERHEAD = TAG_BITS >> 3;

    private static final SecureRandom random = new SecureRandom();

    public static byte[] encrypt(byte[] decrypted, SecretKeySpec aes) throws InvalidKeyException, IllegalArgumentException {
        final ByteBuffer output = ByteBuffer.allocate(NONCE_SIZE + decrypted.length + OVERHEAD);
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException error) {
            throw new IllegalArgumentException(error.getMessage());
        }
        
        final byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        final GCMParameterSpec gcm = new GCMParameterSpec(TAG_BITS, nonce);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, aes, gcm);
        } catch (InvalidKeyException error) {
            if (aes.getAlgorithm() == ALGORITHM && aes.getEncoded().length > 16) {
                throw new InvalidKeyException(error.getMessage() + ": does your JVM allow keys larger than 128-bit?");
            }
            throw error;
        } catch (InvalidAlgorithmParameterException error) {
            throw new IllegalArgumentException(error.getMessage());
        }

        output.put(nonce);
        try {
            output.put(cipher.doFinal(decrypted));
        } catch(IllegalBlockSizeException | BadPaddingException error) {
            throw new IllegalArgumentException(error.getMessage());
        }

        return output.array();
    }

    public static byte[] encrypt(String decrypted, SecretKeySpec aes) throws InvalidKeyException, IllegalArgumentException {
        return encrypt(decrypted.getBytes(), aes);
    }

    public static byte[] encrypt(byte[] decrypted, byte[] aesBytes) throws InvalidKeyException, IllegalArgumentException {
        return encrypt(decrypted, new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }

    public static byte[] encrypt(String decrypted, byte[] aesBytes) throws InvalidKeyException, IllegalArgumentException {
        return encrypt(decrypted.getBytes(), new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }

    public static byte[] decrypt(byte []encrypted, SecretKeySpec aes) throws InvalidKeyException, IllegalArgumentException {
        if (encrypted.length < NONCE_SIZE + OVERHEAD) {
            throw new IllegalArgumentException("Encrypted message size is too short");
        }

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException error) {
            throw new IllegalArgumentException(error.getMessage());
        }
        final byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_SIZE);
        final byte[] encryptedAndTag = Arrays.copyOfRange(encrypted, NONCE_SIZE, encrypted.length);
        final GCMParameterSpec gcm = new GCMParameterSpec(TAG_BITS, nonce);
        try {
            cipher.init(Cipher.DECRYPT_MODE, aes, gcm);
        } catch (InvalidAlgorithmParameterException error) {
            throw new IllegalArgumentException(error.getMessage());
        }
        
        try {
            return cipher.doFinal(encryptedAndTag);
        } catch(BadPaddingException | IllegalBlockSizeException error) {
            throw new IllegalArgumentException(error.getMessage());
        }
    }

    public static byte[] decrypt(String encrypted, SecretKeySpec aes) throws InvalidKeyException, IllegalArgumentException {
        return decrypt(encrypted.getBytes(), aes);
    }

    public static byte[] decrypt(byte []encrypted, byte[] aesBytes) throws InvalidKeyException, IllegalArgumentException {
        return decrypt(encrypted, new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }

    public static byte[] decrypt(String encrypted, byte[] aesBytes) throws InvalidKeyException, IllegalArgumentException {
        return decrypt(encrypted.getBytes(), new Key(aesBytes, Key.Type.MESSAGE).toSecretKey());
    }
}   