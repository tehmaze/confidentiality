package io.maze.confidentiality;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Authenticate {
    public static String ALGORITHM = "HmacSHA256";
    public static int SIGNATURE_LENGTH = 32;

    static byte[] signature(byte[] message, SecretKeySpec key) throws  InvalidKeyException, NoSuchAlgorithmException {
        final Mac hmac = Mac.getInstance(ALGORITHM);
        hmac.init(key);
        hmac.update(message);
        return hmac.doFinal();
    }

    static byte[] signature(String message, SecretKeySpec key) throws InvalidKeyException, NoSuchAlgorithmException {
        return signature(message.getBytes(), key);
    }


    static byte[] signature(byte[] message, byte []key) throws InvalidKeyException, NoSuchAlgorithmException {
        return signature(message, new Key(key, Key.Type.AUTHENTICATION).toSecretKey());
    }

    static byte[] signature(String message, byte []key) throws InvalidKeyException, NoSuchAlgorithmException{
        return signature(message.getBytes(), new Key(key, Key.Type.AUTHENTICATION).toSecretKey());
    }

    static boolean verify(byte[] message, SecretKeySpec key) throws InvalidKeyException, NoSuchAlgorithmException {
        if (message.length < SIGNATURE_LENGTH) {
            return false;
        }

        final byte[] signed = Arrays.copyOfRange(message, 0, message.length - SIGNATURE_LENGTH);
        final byte[] verify = Arrays.copyOfRange(message, message.length - SIGNATURE_LENGTH, message.length);
        final byte[] signature = signature(signed, key);
        return MessageDigest.isEqual(signature, verify);
    }

    static boolean verify(String message, SecretKeySpec key) throws InvalidKeyException, NoSuchAlgorithmException {
        return verify(message.getBytes(), key);
    }

    static boolean verify(byte[] message, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
        return verify(message, new Key(key, Key.Type.AUTHENTICATION).toSecretKey());
    }

    static boolean verify(String message, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
        return verify(message.getBytes(), new Key(key, Key.Type.AUTHENTICATION).toSecretKey());
    }
}