import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import io.jsonwebtoken.Jwts;

public class VulnerableCrypto {
    public void rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }

    public byte[] md5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public void aesCbc() throws Exception {
        Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public void des() throws Exception {
        Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public void ecdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        Signature.getInstance("SHA256withECDSA");
    }

    public void ecdh() throws Exception {
        KeyAgreement.getInstance("ECDH");
    }

    public void dh() throws Exception {
        KeyPairGenerator.getInstance("DH");
    }

    public String jwt() {
        return Jwts.builder().compact();
    }
}
