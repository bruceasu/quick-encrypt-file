package me.asu.quick.util;

import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public abstract class AbstractDigest {

    /**
     * 从数据文件计算出数字签名
     *
     * @param algorithm 算法，比如 "SHA1" 或者 "MD5" 等
     * @param f         文件
     * @return 数字签名
     */
    public static String digest(String algorithm, File f) throws IOException {
        return digest(algorithm, Files.newInputStream(f.toPath()));
    }

    /**
     * 从流计算出数字签名，计算完毕流会被关闭
     *
     * @param algorithm 算法，比如 "SHA1" 或者 "MD5" 等
     * @param ins       输入流
     * @return 数字签名
     */
    public static String digest(String algorithm, InputStream ins) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            byte[] bs  = new byte[1024];
            int    len = 0;
            while ((len = ins.read(bs)) != -1) {
                md.update(bs, 0, len);
            }

            byte[] hashBytes = md.digest();

            return fixedHexString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw Exceptions.wrapThrow(e);
        } catch (FileNotFoundException e) {
            throw Exceptions.wrapThrow(e);
        } catch (IOException e) {
            throw Exceptions.wrapThrow(e);
        } finally {
            safeClose(ins);
        }
    }

    public static boolean safeClose(Closeable cb) {
        if (null != cb) {
            try {
                cb.close();
            } catch (IOException e) {
                return false;
            }
        }
        return true;
    }
    /**
     * 从字符串计算出数字签名
     *
     * @param algorithm 算法，比如 "SHA1" 或者 "MD5" 等
     * @param cs        字符串
     * @return 数字签名
     */
    public static String digest(String algorithm, String cs) {
        return digest(algorithm, Bytes.toBytes(null == cs ? "" : cs), null, 1);
    }

    public static String digest(String algorithm, byte[] data) {
        return digest(algorithm, data, null, 1);
    }

    /**
     * 从字节数组计算出数字签名
     *
     * @param algorithm  算法，比如 "SHA1" 或者 "MD5" 等
     * @param bytes      字节数组
     * @param salt       随机字节数组
     * @param iterations 迭代次数
     * @return 数字签名
     */
    public static String digest(String algorithm,
                                byte[] bytes,
                                byte[] salt,
                                int iterations) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            if (salt != null) {
                md.update(salt);
            }

            byte[] hashBytes = md.digest(bytes);

            for (int i = 1; i < iterations; i++) {
                md.reset();
                hashBytes = md.digest(hashBytes);
            }

            return fixedHexString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw Exceptions.wrapThrow(e);
        }
    }

    public static String fixedHexString(byte[] hashBytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < hashBytes.length; i++) {
            sb.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16)
                             .substring(1));
        }

        return sb.toString();
    }
}
