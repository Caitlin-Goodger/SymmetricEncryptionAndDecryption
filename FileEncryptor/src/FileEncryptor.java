import com.sun.javafx.scene.traversal.Algorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void encrypt(String inFile, String outFile, Path tempDir) throws BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        Base64.Encoder en = Base64.getEncoder();
        String eKey = en.encodeToString(key);
        String eIV = en.encodeToString(initVector);
        System.out.println("Random key=" + eKey);
        System.out.println("initVector=" + eIV);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        String info = ALGORITHM + " " + 16;

        for (int i = info.length()-1; i<15;i++) {
            info = info + " ";
        }
        byte[] infoByte = info.getBytes();

        //Look for files here

        final Path encryptedPath = tempDir.resolve(outFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inFile);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            fout.write(infoByte);
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            throw new BadPaddingException();
        }

        System.out.println("Encryption finished, saved at " + encryptedPath);
    }

    public static void encryptWithKey(String inFile, String outFile, Path tempDir, String keyStr) throws BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        SecureRandom sr = new SecureRandom();
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] key = decoder.decode(keyStr);
        //sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        Base64.Encoder en = Base64.getEncoder();
        String eKey = en.encodeToString(key);
        String eIV = en.encodeToString(initVector);
        //System.out.println("Byte IV = " + en.encode(initVector));
        System.out.println("Random key=" + eKey);
        System.out.println("initVector=" + eIV);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        String info = ALGORITHM + " " + 128;

        for (int i = info.length()-1; i<15;i++) {
            info = info + " ";
        }
        byte[] infoByte = info.getBytes();

        final Path encryptedPath = tempDir.resolve(outFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inFile);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            fout.write(infoByte);
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            throw new BadPaddingException();
        }

        System.out.println("Encryption finished, saved at " + encryptedPath);
    }

    public static void encryptWithPassword(String inFile, String outFile, Path tempDir, String password) throws BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
       SecureRandom sr = new SecureRandom();

        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);


        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), initVector, 1000, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secret,iv);
        byte[] keyBytes = secret.getEncoded();
        Base64.Encoder en = Base64.getEncoder();
        String eKey = en.encodeToString(keyBytes);
        String eIV = en.encodeToString(initVector);
        System.out.println("Random key=" + eKey);
        System.out.println("initVector=" + eIV);

        String info = ALGORITHM + " " + 128;

        for (int i = info.length()-1; i<15;i++) {
            info = info + " ";
        }
        byte[] infoByte = info.getBytes();

        final Path encryptedPath = tempDir.resolve(outFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inFile);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            fout.write(infoByte);
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            throw new BadPaddingException();
        }

        System.out.println("Encryption finished, saved at " + encryptedPath);
    }

    public static void encryptAESwithLength(String inFile, String outFile, Path tempDir, String keyLength, String password) throws BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        SecureRandom sr = new SecureRandom();

        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);

        int len = Integer.parseInt(keyLength);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), initVector, 1000, len);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secret,iv);
        byte[] keyBytes = secret.getEncoded();
        Base64.Encoder en = Base64.getEncoder();
        String eKey = en.encodeToString(keyBytes);
        String eIV = en.encodeToString(initVector);
        System.out.println("Random key=" + eKey);
        System.out.println("initVector=" + eIV);
        String info = ALGORITHM + " " + keyLength;

        for (int i = info.length()-1; i<15;i++) {
            info = info + " ";
        }
        byte[] infoByte = info.getBytes();

        final Path encryptedPath = tempDir.resolve(outFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inFile);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            fout.write(infoByte);
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            throw new BadPaddingException();
        }

        System.out.println("Encryption finished, saved at " + encryptedPath);
    }

    public static void encryptBlowfishwithLength(String inFile, String outFile, Path tempDir, String keyLength, String password) throws BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        SecureRandom sr = new SecureRandom();

        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);

        int len = Integer.parseInt(keyLength);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), initVector, 1000, len);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "Blowfish");
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] keyBytes = secret.getEncoded();
        Base64.Encoder en = Base64.getEncoder();
        String eKey = en.encodeToString(keyBytes);
        String eIV = en.encodeToString(initVector);
        System.out.println("Random key=" + eKey);
        System.out.println("initVector=" + eIV);
        String info = "Blowfish " + keyLength;

        //Look for files here
        for (int i = info.length()-1; i<15;i++) {
            info = info + " ";
        }
        byte[] infoByte = new byte[16];
        infoByte = info.getBytes();

        final Path encryptedPath = tempDir.resolve(outFile);
        try (InputStream fin = FileEncryptor.class.getResourceAsStream(inFile);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(initVector);
            fout.write(infoByte);
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            throw new BadPaddingException();
        }

        System.out.println("Encryption finished, saved at " + encryptedPath);
    }

    public static void decryptWithPassword(String inFile, String outFile, String password, Path tempDir) throws BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        final Path encryptedPath = tempDir.resolve(inFile);
        final Path decryptedPath = tempDir.resolve(outFile);
        InputStream encryptedData = Files.newInputStream(encryptedPath);
        byte[] initVector = new byte[16];
        encryptedData.read(initVector);
        byte[] algoandLength = new byte[16];
        encryptedData.read(algoandLength);
        String algo = new String(algoandLength);
        String[] splot = algo.split(" ");
        int keyLength = Integer.parseInt(splot[1]);
        String alg = splot[0];
        Cipher cipher = Cipher.getInstance(CIPHER);
        if(alg.equals("Blowfish")) {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), initVector, 1000, keyLength);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "Blowfish");
            IvParameterSpec iv = new IvParameterSpec(initVector);
            cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.DECRYPT_MODE, secret);
        } else if (alg.equals("AES")) {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), initVector, 1000, keyLength);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(initVector);
            cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secret,iv);
        }
        try (
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            throw new BadPaddingException();
        }
        System.out.println("Decryption complete, open " + decryptedPath);
    }

    public static void decrypt(String inFile, String outFile, String keyStr, String IVStr, Path tempDir) throws IllegalArgumentException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] key = decoder.decode(keyStr);
        final Path encryptedPath = tempDir.resolve(inFile);
        final Path decryptedPath = tempDir.resolve(outFile);
        InputStream encryptedData;
        try {
            encryptedData = Files.newInputStream(encryptedPath);
        } catch (NoSuchFileException e) {
            throw new IOException();
        }
        byte[] iniVector = new byte[16];
        encryptedData.read(iniVector);
        byte[] algoandLength = new byte[16];
        encryptedData.read(algoandLength);
        byte[] initVector = new byte[16];
        try {
            initVector = decoder.decode(IVStr);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException();
        }
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        try (
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            throw new BadPaddingException();
        }
        System.out.println("Decryption complete, open " + decryptedPath);
    }

    public static void decryptNoIv(String inFile, String outFile, String keyStr, Path tempDir) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, BadPaddingException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] key = decoder.decode(keyStr);
        final Path encryptedPath = tempDir.resolve(inFile);
        final Path decryptedPath = tempDir.resolve(outFile);
        InputStream encryptedData;
        try {
            encryptedData = Files.newInputStream(encryptedPath);
        } catch (NoSuchFileException e) {
            throw new IOException();
        }
        byte[] initVector = new byte[16];
        encryptedData.read(initVector);
        byte[] algoandLength = new byte[16];
        encryptedData.read(algoandLength);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        try (
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
             OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            throw new BadPaddingException();
        }
        System.out.println("Decryption complete, open " + decryptedPath);
    }


    public static void readInfo(String inFile, Path tempDir) throws IOException{
        final Path encryptedPath = tempDir.resolve(inFile);
        InputStream encryptedData;
        try {
            encryptedData = Files.newInputStream(encryptedPath);
        } catch (NoSuchFileException e) {
            throw new IOException();
        }
        byte[] initVector = new byte[16];
        encryptedData.read(initVector);
        byte[] algoandLength = new byte[16];
        encryptedData.read(algoandLength);
        String algo = new String(algoandLength);
        System.out.println(algo);
    }
    public final FileEncryptor clone() throws java.lang.CloneNotSupportedException {
        throw new java.lang.CloneNotSupportedException();
    }

    private final void readObject(ObjectInputStream in) throws java.io.IOException {
        throw new java.io.IOException("Class cannot be deserialized");
    }

    private final void writeObject(ObjectOutputStream out) throws java.io.IOException {
        throw new java.io.IOException("Object cannot be serialized");
    }

    public static void main(String[] args){
        try {
            final Path tempDir = Paths.get("");
            if(args.length > 0) {
                String encordec = args[0];
                if (encordec.equals("enc")) {
                    if (args.length == 3) {
                        String inFile = args[1];
                        String outFile = args[2];
                        encrypt(inFile, outFile, tempDir);
                    } else if (args.length == 4) {
                        String key = args[1];
                        if (key.contains("A==") || key.contains("Q==") || key.contains("g==") || key.contains("w==")) {
                            String inFile = args[2];
                            String outFile = args[3];
                            encryptWithKey(inFile, outFile, tempDir, key);
                        } else {
                            String inFile = args[2];
                            String outFile = args[3];
                            encryptWithPassword(inFile, outFile, tempDir, key);
                        }

                    } else if (args.length == 6) {
                        String algo = args[1];
                        String length = args[2];
                        String password = args[3];
                        String inFile = args[4];
                        String outFile = args[5];
                        if (algo.equals("AES")) {
                            encryptAESwithLength(inFile, outFile, tempDir, length, password);
                        } else if (algo.equals("Blowfish")) {
                            encryptBlowfishwithLength(inFile, outFile, tempDir, length, password);
                        }
                    } else if (args.length == 5) {
                        String length = args[1];
                        String password = args[2];
                        String inFile = args[3];
                        String outFile = args[4];
                        encryptAESwithLength(inFile, outFile, tempDir, length, password);
                    } else {
                        System.out.println("Please use the correct number of arguments");
                    }
                } else if (encordec.equals("dec")) {
                    if (args.length == 5) {
                        String key = args[1];
                        String iv = args[2];
                        String inFile = args[3];
                        String outFile = args[4];
                        decrypt(inFile, outFile, key, iv, tempDir);
                    } else if (args.length == 4) {
                        String key = args[1];
                        if (key.contains("A==") || key.contains("Q==") || key.contains("g==") || key.contains("w==")) {
                            String inFile = args[2];
                            String outFile = args[3];
                            decryptNoIv(inFile, outFile, key, tempDir);
                        } else {
                            String inFile = args[2];
                            String outFile = args[3];
                            decryptWithPassword(inFile, outFile, key, tempDir);
                        }
                    } else {
                        System.out.println("Please use the correct number of arguments");
                    }
                } else if (encordec.equals("info")) {
                    if (args.length == 2) {
                        String inFile = args[1];
                        readInfo(inFile, tempDir);
                    } else {
                        System.out.println("Please use the correct number of arguments");
                    }
                } else {
                    System.out.println("Please give enc, dec or info as the first argument. ");
                }
            } else {
                System.out.println("Please give arguments. ");
            }
        } catch (IOException e ) {
            System.out.println("Input or Output file is incorrect. Please try again with the correct file names. ");
        } catch (InvalidKeyException e ) {
            System.out.println("Your key is incorrect. Please try again with the correct key. Also check that the key length is valid");
        } catch (BadPaddingException e) {
            System.out.println("Your file was unable to decrypt. Check if the password is correct and try again");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("There was no algorithm found that matches. Please try again with a valid algorithm");
        } catch (InvalidKeySpecException e) {
            System.out.println("There was no key specifications found that matches. Please try again with a valid key specification");
        } catch (NoSuchPaddingException e) {
            System.out.println("There is no padding found. Please try again");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("There are invalid Algorithm Parameters. Please try again with valid parameters");
        } catch (IllegalArgumentException e) {
            System.out.println("There are invalid Parameters. Please try again with valid parameters. Check the key and IV values ");
        } catch (NullPointerException e) {
            System.out.println("The input file is invalid. Please try again the with correct file name. ");
        }
    }
}
