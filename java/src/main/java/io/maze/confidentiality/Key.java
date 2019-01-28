package io.maze.confidentiality;

import java.security.InvalidKeyException;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

public class Key {
    public enum Type {
        AUTHENTICATION, MESSAGE
    }

    Key(byte[] raw, Type kind) throws InvalidKeyException {
        load(raw, kind);
    }

    Key(String base64, Type kind) throws InvalidKeyException {
        load(Base64.getDecoder().decode(base64), kind);
    }

    private void load(byte[] raw, Type kind) throws InvalidKeyException {
        switch (kind) {
        case AUTHENTICATION:
            key = new SecretKeySpec(raw, Authenticate.ALGORITHM);
            break;
        case MESSAGE:
            if (!(raw.length == 16 || raw.length == 24 || raw.length == 32)) {
                throw new InvalidKeyException("Expected 128-, 192- or 256-bit key");
            }
            key = new SecretKeySpec(raw, Message.ALGORITHM);
            break;
        default:
            throw new InvalidKeyException();
        }
    }

    public int getBits() {
        return key.getEncoded().length << 3;
    }

    public SecretKeySpec toSecretKey() {
        return key;
    }

    private SecretKeySpec key;
}