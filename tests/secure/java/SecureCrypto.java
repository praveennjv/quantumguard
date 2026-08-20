import java.security.MessageDigest;
import javax.crypto.Cipher;

public class SecureCrypto {
    public byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public void aesGcm() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
