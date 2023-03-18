package me.asu.quick.util;

import static me.asu.quick.ErrorCode.IO_ERROR;
import static me.asu.quick.util.GzipUtils.gzip;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/*
PBEWITHHMACSHA1ANDAES_128
PBEWITHHMACSHA1ANDAES_256
PBEWITHHMACSHA224ANDAES_128
PBEWITHHMACSHA224ANDAES_256
PBEWITHHMACSHA256ANDAES_128
PBEWITHHMACSHA256ANDAES_256
PBEWITHHMACSHA384ANDAES_128
PBEWITHHMACSHA384ANDAES_256
PBEWITHHMACSHA512ANDAES_128
PBEWITHHMACSHA512ANDAES_256
PBEWITHMD5ANDDES
PBEWITHMD5ANDTRIPLEDES
PBEWITHSHA1ANDDESEDE
PBEWITHSHA1ANDRC2_128
PBEWITHSHA1ANDRC2_40
PBEWITHSHA1ANDRC4_128
PBEWITHSHA1ANDRC4_40
*/
public class PBEUtils {
    public static byte[] CRLF = "\r\n".getBytes(StandardCharsets.UTF_8);
    public static  char       LF        = '\n';
    public static String       VERSION_1_0   = "GZB version 1.0";
    public static String       VERSION   = VERSION_1_0;
    public static final String ALGORITHM = "PBEWITHHMACSHA512ANDAES_256";

    //Security.addProvider(new com.sun.crypto.provider.SunJCE());

    public static final int ITERATION_COUNT = 8;


    public static byte[] initSalt() throws Exception {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(8);
    }

    // 16 bytes, 128bits
    public static byte[] IV   = "1234567890ABCDEF".getBytes();
    // 32 bytes, 256bits
    public static byte[] SALT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
            .getBytes();


    private static Key toKey(String password) throws Exception {
        PBEKeySpec       keySpec    = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey        secretKey  = keyFactory.generateSecret(keySpec);

        return secretKey;
    }

    // String outFileName = Md5Utils.md5(fileIn.getAbsolutePath());
    public static Path encryptToGzbFile(Path in, Path outDir, String password)
    throws Exception {
        if (!Files.isDirectory(outDir)) Files.createDirectories(outDir);
        if (!Files.isRegularFile(in)) throw new FileNotFoundException(in.toString() + " is not found.");

        Path fileName = in.getFileName();
        String outFileName = Md5Utils.md5(in.toAbsolutePath().toString()) +".gzb";
        Path outPath = Paths.get(outDir.toAbsolutePath().toString(), outFileName);
        OutputStream outputStream = Files.newOutputStream(outPath);
        InputStream inputStream = Files.newInputStream(in);
        long            start  = System.currentTimeMillis();
        long size = Files.size(in);
        String encryptedFileName = encryptString("filename:" + fileName.toString(), password);
        String encryptedFileSize = encryptString("filesize:" + size, password);
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, ITERATION_COUNT, ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        outputStream.write(VERSION.getBytes(StandardCharsets.UTF_8));

        outputStream.write(LF);
        outputStream.write(LF);
        // write the metadata
        outputStream.write(encryptedFileName.getBytes(StandardCharsets.UTF_8));
        outputStream.write(LF);
        outputStream.write(encryptedFileSize.getBytes(StandardCharsets.UTF_8));
        outputStream.write(LF);
        outputStream.write("---\n".getBytes(StandardCharsets.UTF_8));
        encryptGzb(inputStream, outputStream, cipher);
        long            end  = System.currentTimeMillis();
        final long cost = end - start;
        System.err.printf("Cost %s ms, %d bytes/s. %s => %s.%n",
                cost, Files.size(in)*1000/cost, in, outFileName);
        return outPath;
    }

    private static void encryptGzb(InputStream in, OutputStream pos, Cipher cipher)
    throws IOException {
        Path tf = Files.createTempFile("gz-", ".gz");
        Path tf2 = Files.createTempFile("e-", ".e");
        //step1
        gzip(in, tf.toString());
        safeClose(in);
        //step2
        try(InputStream inputStream = Files.newInputStream(tf);
        OutputStream outputStream = Files.newOutputStream(tf2)) {
            byte buffer[] = new byte[4096];
            int len = 0;
            while (true) {
                try {
                    len = inputStream.read(buffer);
                    if (len == -1) {
                        break;
                    } else if (len == buffer.length) {
                        byte[] bytes = cipher.update(buffer, 0, len);
                        outputStream.write(bytes);
                    } else {
                        byte[] bytes = cipher.doFinal(buffer, 0, len);
                        outputStream.write(bytes);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    break;
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                    break;
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                    break;
                }
            }
        }
        Files.deleteIfExists(tf);

        //step3
        try(InputStream inputStream = Files.newInputStream(tf2)) {
            Encoder mimeEncoder = Base64.getMimeEncoder();
            byte buffer[] = new byte[5700];
            int len = 0;
            while (true) {
                try {
                    len = inputStream.read(buffer);
                    if (len == -1) {
                        break;
                    } else if (len == buffer.length) {
                        byte[] buffer2 = mimeEncoder.encode(buffer);
                        pos.write(buffer2);

                        pos.write(CRLF);
                    } else {
                        byte[] bytes = new byte[len];
                        System.arraycopy(buffer,0,bytes, 0, len);
                        byte[] buffer2 = mimeEncoder.encode(bytes);
                        pos.write(buffer2);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    break;
                }
            }
        }
        safeClose(pos);
        Files.deleteIfExists(tf2);
    }

    public static Map<String, String> readGzbMetaInfo(Path path, String pass) {
        Map<String, String> meta = new TreeMap<>();
        try(BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String ver = reader.readLine();
            if (!PBEUtils.VERSION.equals(ver)) {
                return Collections.emptyMap();
            }
            meta.put("version", ver);
            // skip 1
            reader.readLine();
            do {
                String line = reader.readLine();
                if ("---".equals(line)) {
                    break;
                }
                String decrypt = decryptString(line, pass);
                String[] split = decrypt.split(":", 2);
                if (split.length == 2) meta.put(split[0], split[1]);
            } while(true);

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Can't read the file.");
            System.exit(IO_ERROR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return meta;
    }

    public static Path decryptToGzbFile(Path in, Path outDir, String password)
    throws Exception {
        if (!Files.isDirectory(outDir)) Files.createDirectories(outDir);
        if (!Files.isRegularFile(in)) throw new FileNotFoundException(in.toString() + " is not found.");
        // read the header
        Map<String, String>  meta = readGzbMetaInfo(in, password);
        if (meta == null || !meta.containsKey("version")) {
            throw Exceptions.makeThrow("It's not an accepted file");
        }
        String version = meta.get("version");
        String fileName = meta.get("filename");
        Path outPath = Paths.get(outDir.toAbsolutePath().toString(), fileName);

        long start = System.currentTimeMillis();
        Key key = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, ITERATION_COUNT, ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        decryptGzb(in, outPath, cipher);
        long end  = System.currentTimeMillis();
        final long cost = end - start;
        System.err.printf("Cost %s ms, %d bytes/s. %s => %s.%n",
                cost, Files.size(in)*1000/cost, in, outPath);
        return outPath;
    }

    private static void decryptGzb(Path in, Path outPath, Cipher cipher)
    throws IOException {
        try(BufferedReader reader = Files.newBufferedReader(in, StandardCharsets.UTF_8);) {
            // skip the meta
            do {
                String line = reader.readLine();
                if("---".equals(line)) break;
            }while(true);
            // step1 decode the data to a temp file;
            Path tf1 = Files.createTempFile("e-", ".e");
            try(OutputStream os = Files.newOutputStream(tf1)) {
                do {
                    String line = reader.readLine();
                    if (line == null)
                        break;
                    byte[] decode = Base64.getDecoder().decode(line);
                    os.write(decode);
                } while (true);
            }
            // step2 decrypt to a temp file.
            Path tf2 = Files.createTempFile("gz-", ".gz");
            try(InputStream is = Files.newInputStream(tf1);
                    OutputStream os = Files.newOutputStream(tf2)) {
                byte buffer[] = new byte[4096];
                int len = 0;
                while (true) {
                    try {
                        len = is.read(buffer);
                        if (len == -1) {
                            break;
                        } else if (len == buffer.length) {
                            byte[] bytes = cipher.update(buffer, 0, len);
                            os.write(bytes);
                        } else {
                            byte[] bytes = cipher.doFinal(buffer, 0, len);
                            os.write(bytes);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        break;
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                        break;
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                        break;
                    }
                }
            }
            Files.deleteIfExists(tf1);

            // step3 gunzip
            GzipUtils.gunzip(tf2, outPath);
        }
    }

    public static void encryptFile(File fileIn, File fileOut, String password)
    throws Exception {
        encryptFile(fileIn, fileOut, password, SALT);
    }

    public static void encryptFile(File fileIn,
                                   File fileOut,
                                   String password,
                                   byte[] salt) throws Exception {
        Objects.requireNonNull(fileIn);
        Objects.requireNonNull(fileOut);
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        InputStream  in = Files.newInputStream(fileIn.toPath());
        OutputStream os = Files.newOutputStream(fileOut.toPath());
        copy(in, os, cipher);
        System.out.println("完成加密 " + fileIn + " => " + fileOut);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
    }


    public static void decryptFile(File fileIn, File fileOut, String password)
    throws Exception {
        decryptFile(fileIn, fileOut, password, SALT);
    }

    public static void decryptFile(File fileIn,
                                   File fileOut,
                                   String password,
                                   byte[] salt) throws Exception {
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        InputStream  in = Files.newInputStream(fileIn.toPath());
        OutputStream os = Files.newOutputStream(fileOut.toPath());
        copy(in, os, cipher);

        System.out.println("完成解密 " + fileIn + " => " + fileOut);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
    }

    public static void encryptContentToFile(String input,
                                     File fileOut,
                                     String password) throws Exception {
        encryptContentToFile(input, fileOut, password, SALT);
    }

    public static void encryptContentToFile(String input,
                                     File fileOut,
                                     String password,
                                     byte[] salt) throws Exception {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        encryptContentToFile(bytes, fileOut, password, salt);
    }

    public static void encryptContentToFile(byte[] input,
                                     File fileOut,
                                     String password,
                                     byte[] salt) throws Exception {
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        InputStream  in = new ByteArrayInputStream(input);
        OutputStream os = Files.newOutputStream(fileOut.toPath());
        copy(in, os, cipher);

        System.out.println("完成加密, 寫入 " + fileOut);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
    }

    public static void decryptToFile(byte[] input,
                                     File fileOut,
                                     String password) throws Exception {
        decryptToFile(input, fileOut, password, SALT);
    }

    public static void decryptToFile(byte[] input,
                                     File fileOut,
                                     String password,
                                     byte[] salt) throws Exception {
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        InputStream  in = new ByteArrayInputStream(input);
        OutputStream os = Files.newOutputStream(fileOut.toPath());
        copy(in, os, cipher);

        System.out.println("完成解密, 寫入 " + fileOut);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
    }

    public static byte[] encryptFile(File fileIn, String password)
    throws Exception {
        return encryptFile(fileIn, password, SALT);
    }

    public static byte[] encryptFile(File fileIn, String password, byte[] salt)
    throws Exception {
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        InputStream           in   = Files.newInputStream(fileIn.toPath());
        ByteArrayOutputStream baos = new ByteArrayOutputStream(4096);
        copy(in, baos, cipher);

        System.out.println("完成加密 " + fileIn);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
        return baos.toByteArray();
    }

    public static byte[] decryptFile(File fileIn, String password)
    throws Exception {
        return decryptFile(fileIn, password, SALT);
    }

    public static byte[] decryptFile(File fileIn, String password, byte[] salt)
    throws Exception {
        long            start  = System.currentTimeMillis();
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        InputStream           in   = Files.newInputStream(fileIn.toPath());
        ByteArrayOutputStream baos = new ByteArrayOutputStream(4096);
        copy(in, baos, cipher);

        System.out.println("完成解密 " + fileIn);
        long end = System.currentTimeMillis();
        System.out.println("花費:  " + (end - start) + " 毫秒。");
        return baos.toByteArray();
    }

    public static PipedInputStream encryptToStream(final InputStream in,
                                                   final String password)
    throws Exception {
        return encryptToStream(in, password, SALT);
    }

    public static PipedInputStream encryptToStream(final InputStream in,
                                                   final String password,
                                                   final byte[] salt)
    throws Exception {
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

        final PipedInputStream  pis = new PipedInputStream();
        final PipedOutputStream pos = new PipedOutputStream(pis);
        new Thread() {
            {
                setDaemon(true);
                start();
            }

            @Override
            public void run() {
                copy(in, pos, cipher);
            }
        };

        return pis;
    }

    public static PipedInputStream decryptToStream(final InputStream in,
                                                   final String password)
    throws Exception {
        return decryptToStream(in, password, SALT);
    }

    public static PipedInputStream decryptToStream(final InputStream in,
                                                   final String password,
                                                   final byte[] salt)
    throws Exception {
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt,
                                                          ITERATION_COUNT,
                                                          ivSpec);
        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        final PipedInputStream  pis = new PipedInputStream();
        final PipedOutputStream pos = new PipedOutputStream(pis);
        new Thread() {
            {
                setDaemon(true);
                start();
            }

            @Override
            public void run() {
                copy(in, pos, cipher);
            }
        };

        return pis;
    }

    public static void copy(InputStream in, OutputStream pos, Cipher cipher) {
        byte buffer[] = new byte[4096];
        int  len      = 0;
        while (true) {
            try {
                len = in.read(buffer);
                if (len == -1) {
                    break;
                } else if (len == buffer.length) {
                    byte[] bytes = cipher.update(buffer, 0, len);
                    pos.write(bytes);
                } else {
                    byte[] bytes = cipher.doFinal(buffer, 0, len);
                    pos.write(bytes);
                }
            } catch (IOException e) {
                e.printStackTrace();
                break;
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
                break;
            } catch (BadPaddingException e) {
                e.printStackTrace();
                break;
            }
        }
        safeClose(in);
        safeClose(pos);
    }

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException e) {
                // ingored.
            }
        }
    }

    public static String encryptString(String data, String password)
    throws Exception {
        return encryptString(data, password, SALT);
    }

    public static String encryptString(String data,
                                       String password,
                                       byte[] salt) throws Exception {
        Encoder encoder = Base64.getEncoder();
        byte[]  bytes   = data.getBytes(StandardCharsets.UTF_8);
        byte[]  encrypt = encrypt(bytes, password, salt);
        return encoder.encodeToString(encrypt);
    }

    public static String decryptString(String data, String password)
    throws Exception {
        return decryptString(data, password, SALT);
    }

    public static String decryptString(String data,
                                       String password,
                                       byte[] salt) throws Exception {
        Decoder decoder = Base64.getDecoder();
        byte[]  decode  = decoder.decode(data);
        byte[]  decrypt = decrypt(decode, password, salt);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    public static byte[] encrypt(byte[] data, String password)
    throws Exception {
        return encrypt(data, password, SALT);
    }

    public static byte[] encrypt(byte[] data, String password, byte[] salt)
    throws Exception {
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec =
                new PBEParameterSpec(salt, ITERATION_COUNT, ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String password)
    throws Exception {
        return decrypt(data, password, SALT);
    }

    public static byte[] decrypt(byte[] data, String password, byte[] salt)
    throws Exception {
        Key             key    = toKey(password);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        PBEParameterSpec paramSpec =
                new PBEParameterSpec(salt, ITERATION_COUNT, ivSpec);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
//        String data     = "test";
//        String password = "abc";
//        byte[] salt     = initSalt();
//        System.out.println("origin: " + data);
//        String d = encryptString(data, password, salt);
//        System.out.println("encrypt: " + d);
//        String d2 = decryptString(d, password, salt);
//        System.out.println("decrypt: " + d2);

        Path target = encryptToGzbFile(Paths.get("d:\\suk\\Videos\\catoon\\种子特务（碧奇魂）3.mp4"), Paths
                .get("target"), "12345678");
        System.out.println("output: " + target);
    }

}
