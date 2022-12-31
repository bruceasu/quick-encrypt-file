package me.asu.quick.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public abstract class Md5Utils extends AbstractDigest {

    static String MD5 = "MD5";

    /**
     * 获取指定文件的 MD5 值
     *
     * @param f 文件
     * @return 指定文件的 MD5 值
     * @see #digest(String, File)
     */
    public static String md5(File f) throws IOException {
        return digest(MD5, f);
    }

    /**
     * 获取指定输入流的 MD5 值
     *
     * @param ins 输入流
     * @return 指定输入流的 MD5 值
     * @see #digest(String, InputStream)
     */
    public static String md5(InputStream ins) {
        return digest(MD5, ins);
    }

    /**
     * 获取指定字符串的 MD5 值
     *
     * @param cs 字符串
     * @return 指定字符串的 MD5 值
     * @see #digest(String, String)
     */
    public static String md5(String cs) {
        return digest(MD5, cs);
    }

    /**
     * 获取指定字符串的 MD5 值
     *
     * @param data 数据
     * @return 指定字符串的 MD5 值
     * @see #digest(String, String)
     */
    public static String md5(byte[] data) {
        return digest(MD5, data);
    }
}
