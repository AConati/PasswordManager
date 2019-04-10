
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.List;
import java.util.ArrayList;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PasswordManager {

    public static final int ITERATIONS = 10000;
    public static final int KEY_LENGTH = 512;

    public static class KeyHash {
        private byte[] hashedKey;
        private String salt;

        public KeyHash(byte[] hashedKey, String salt) {
            this.hashedKey = hashedKey;
            this.salt = salt;
        }

        public byte[] getKey() {
            return this.hashedKey;
        }

        public String getSalt(){
            return this.salt;
        }
    }

    public static boolean authenticate(String master,  KeyHash keyHash) {
        return true;
    }

    public static KeyHash initialize(String master) {
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        String saltString = new String(salt);
        byte[] key = hashPassword(master, salt);
        
        return new KeyHash(key, saltString); //temporary

    }

    public static byte[] hashPassword(String master, byte[] salt) {
        char[] password = master.toCharArray();
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKey key = factory.generateSecret(spec);
            return key.getEncoded();
        } catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptPassword(String master, String salt, String encrypted_password) {
        return "";
    }

    public static String encryptPassword(String master, String salt, String accountPassword) {
        return "";
    }

    public static List<String> changeMaster(String oldMaster, String oldSalt, String newMaster, List<String> encryptedPasswords) {
        return encryptedPasswords;
    }

    public static void main(String[] args) {
        initialize("password");
    }

}
