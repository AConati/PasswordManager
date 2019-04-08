
import java.security.SecureRandom;

import java.util.List;
import java.util.ArrayList;

public class PasswordManager {

    public static final int ITERATIONS = 10000;

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
        SecureRandom.getInstanceStrong().nextBytes(salt);
        String saltString = new String(salt);
        
        return new KeyHash(salt, saltString); //temporary

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

}
