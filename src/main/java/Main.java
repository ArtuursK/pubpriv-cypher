import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    private static final int KEY_SIZE = 1024;

    public static void main (String[] args) throws Exception {
        readAndUsePublicKeyFile();
        //encriptAndDecript();
        //signAndVerify();
    }

    private static void readAndUsePublicKeyFile() throws Exception {
        final String filename = "pubkey2";
        KeyPair keyPair = generateKeyPair();
        savePubKeyToFile(keyPair.getPublic(), filename);

        PublicKey publicKey = readPubKeyFromFile(filename);

        String message = "Secret message 3";
        String encryptedMessage = encrypt(message, publicKey);
        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    private static void encriptAndDecript() throws Exception {
        KeyPair keyPair = generateKeyPair();

        String message = "Secret message";
        String encryptedMessage = encrypt(message, keyPair.getPublic());
        //System.out.println("Encrypted message: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());

        System.out.println("Decrypted message: " + decryptedMessage);
    }

    private static void signAndVerify() throws Exception {
        KeyPair pair = generateKeyPair();

        String signature = sign("foobar", pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify("foobar", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }



    /*
    Instead of passing byte arrays around base 64 encode/decode them because this is a rather common use case in the REST API’s
    */
    private static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    private static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    private static KeyPair generateKeyPair() {
        KeyPairGenerator generator = null;
        KeyPair pair = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE, new SecureRandom());
            pair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return pair;
    }

    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    private static void savePubKeyToFile(PublicKey publicKey, String filename) throws IOException {
        /* save the public key in a file */
        byte[] key = publicKey.getEncoded();
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        fileOutputStream.write(key);
        fileOutputStream.close();
    }

    private static PublicKey readPubKeyFromFile(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
