package me.asu.quick.util;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;

public class Bytes {

    public Bytes() {
    }

    public static void main(String[] args) {
        int x = 16909060;
        byte[] bytes = toBytes(x);
        String ssBefore = Arrays.toString(bytes);
        System.out.println("ssBefore = " + ssBefore);
        ByteBuffer bb = ByteBuffer.wrap(new byte[4]);
        bb.asIntBuffer().put(x);
        String ssBefore2 = Arrays.toString(bb.array());
        System.out.println("ssBefore2 = " + ssBefore2);
        ByteBuffer allocate = ByteBuffer.allocate(4);
        allocate.put(bytes).clear();
        IntBuffer intBuffer = allocate.asIntBuffer();
        int i = intBuffer.get();
        System.out.println("String.valueOf(i, 16) = " + Integer.toHexString(i));
    }

    /**
     * Size of boolean in bytes
     */
    public static final int SIZEOF_BOOLEAN = Byte.SIZE / Byte.SIZE;

    /**
     * Size of byte in bytes
     */
    public static final int SIZEOF_BYTE = SIZEOF_BOOLEAN;

    /**
     * Size of char in bytes
     */
    public static final int SIZEOF_CHAR = Character.SIZE / Byte.SIZE;

    /**
     * Size of double in bytes
     */
    public static final int SIZEOF_DOUBLE = Double.SIZE / Byte.SIZE;

    /**
     * Size of float in bytes
     */
    public static final int SIZEOF_FLOAT = Float.SIZE / Byte.SIZE;

    /**
     * Size of int in bytes
     */
    public static final int SIZEOF_INT = Integer.SIZE / Byte.SIZE;

    /**
     * Size of long in bytes
     */
    public static final int SIZEOF_LONG = Long.SIZE / Byte.SIZE;

    /**
     * Size of short in bytes
     */
    public static final int SIZEOF_SHORT = Short.SIZE / Byte.SIZE;


    /**
     * Estimate of size cost to pay beyond payload in jvm for instance of byte [].
     * Estimate based on study of jhat and jprofiler numbers.
     */
    // JHat says BU is 56 bytes.
    // SizeOf which uses java.lang.instrument says 24 bytes. (3 longs?)
    public static final int ESTIMATED_HEAP_TAX = 16;

    /**
     * empty byte array byte[0];
     */
    public static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * Byte array comparator class.
     */
    public static class ByteArrayComparator implements Comparator<byte[]> {
        /**
         * Constructor
         */
        public ByteArrayComparator() {
            super();
        }

        @Override
        public int compare(byte[] left, byte[] right) {
            return compareTo(left, right);
        }

        public int compare(byte[] b1, int s1, int l1, byte[] b2, int s2, int l2) {
            return compareTo(b1, s1, l1, b2, s2, l2);
        }
    }

    /**
     * Pass this to TreeMaps where byte [] are keys.
     */
    public static Comparator<byte[]> BYTES_COMPARATOR =
            new ByteArrayComparator();

    /**
     * Use comparing byte arrays, byte-by-byte
     */
    public static Comparator<byte[]> BYTES_RAWCOMPARATOR =
            new ByteArrayComparator();

    /**
     * Read byte-array written with a first 4 bytes as length.
     *
     * @param in Input to read from.
     * @return byte array read off <code>in</code>
     * @throws IOException e
     */
    public static byte[] readByteArray(final DataInput in)
            throws IOException {
        int len = in.readInt();
        if (len < 0) {
            throw new NegativeArraySizeException(Integer.toString(len));
        }
        byte[] result = new byte[len];
        in.readFully(result, 0, len);
        return result;
    }

    /**
     * Read byte-array written with a WritableableUtils.vint prefix.
     * IOException is converted to a RuntimeException.
     *
     * @param in Input to read from.
     * @return byte array read off <code>in</code>
     */
    public static byte[] readByteArrayThrowsRuntime(final DataInput in) {
        try {
            return readByteArray(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Write byte-array with a WritableableUtils.vint prefix.
     *
     * @param out output stream to be written to
     * @param b   array to write
     * @throws IOException e
     */
    public static void writeByteArray(final DataOutput out, final byte[] b)
            throws IOException {
        if (b == null) {
            out.writeInt(0);
        } else {
            writeByteArray(out, b, 0, b.length);
        }
    }

    /**
     * Write byte-array to out with a vint length prefix.
     *
     * @param out    output stream
     * @param b      array
     * @param offset offset into array
     * @param length length past offset
     * @throws IOException e
     */
    public static void writeByteArray(final DataOutput out, final byte[] b,
                                      final int offset, final int length)
            throws IOException {
        out.writeInt(length);
        out.write(b, offset, length);
    }

    /**
     * Write byte-array from src to tgt with a vint length prefix.
     *
     * @param tgt       target array
     * @param tgtOffset offset into target array
     * @param src       source array
     * @param srcOffset source offset
     * @param srcLength source length
     * @return New offset in src array.
     */
    public static int writeByteArray(final byte[] tgt, final int tgtOffset,
                                     final byte[] src, final int srcOffset, final int srcLength) {
        byte[] vint = toBytes(srcLength);
        System.arraycopy(vint, 0, tgt, tgtOffset, vint.length);
        int offset = tgtOffset + vint.length;
        System.arraycopy(src, srcOffset, tgt, offset, srcLength);
        return offset + srcLength;
    }

    /**
     * Put bytes at the specified byte array position.
     *
     * @param tgtBytes  the byte array
     * @param tgtOffset position in the array
     * @param srcBytes  array to write out
     * @param srcOffset source offset
     * @param srcLength source length
     * @return incremented offset
     */
    public static int putBytes(byte[] tgtBytes, int tgtOffset, byte[] srcBytes,
                               int srcOffset, int srcLength) {
        System.arraycopy(srcBytes, srcOffset, tgtBytes, tgtOffset, srcLength);
        return tgtOffset + srcLength;
    }
    /**
     * Put a long value out to the specified byte array position.
     *
     * @param bytes  the byte array
     * @param offset position in the array
     * @param val    long to write out
     * @return incremented offset
     * @throws IllegalArgumentException if the byte array given doesn't have
     *                                  enough room at the offset specified.
     */
    public static int putLong(byte[] bytes, int offset, long val) {
        if (bytes.length - offset < SIZEOF_LONG) {
            throw new IllegalArgumentException("Not enough room to put a long at"
                                                       + " offset " + offset + " in a " + bytes.length + " byte array");
        }
        for (int i = offset + 7; i > offset; i--) {
            bytes[i] = (byte) val;
            val >>>= 8;
        }
        bytes[offset] = (byte) val;
        return offset + SIZEOF_LONG;
    }
    /**
     * @param bytes  byte array
     * @param offset offset to write to
     * @param f      float value
     * @return New offset in <code>bytes</code>
     */
    public static int putFloat(byte[] bytes, int offset, float f) {
        return putInt(bytes, offset, Float.floatToRawIntBits(f));
    }

    /**
     * @param bytes  byte array
     * @param offset offset to write to
     * @param d      value
     * @return New offset into array <code>bytes</code>
     */
    public static int putDouble(byte[] bytes, int offset, double d) {
        return putLong(bytes, offset, Double.doubleToLongBits(d));
    }
    /**
     * Write a single byte out to the specified byte array position.
     *
     * @param bytes  the byte array
     * @param offset position in the array
     * @param b      byte to write out
     * @return incremented offset
     */
    public static int putByte(byte[] bytes, int offset, byte b) {
        bytes[offset] = b;
        return offset + 1;
    }
    /**
     * Put a short value out to the specified byte array position.
     *
     * @param bytes  the byte array
     * @param offset position in the array
     * @param val    short to write out
     * @return incremented offset
     * @throws IllegalArgumentException if the byte array given doesn't have
     *                                  enough room at the offset specified.
     */
    public static int putShort(byte[] bytes, int offset, short val) {
        if (bytes.length - offset < SIZEOF_SHORT) {
            throw new IllegalArgumentException("Not enough room to put a short at"
                                                       + " offset " + offset + " in a " + bytes.length + " byte array");
        }
        bytes[offset + 1] = (byte) val;
        val >>= 8;
        bytes[offset] = (byte) val;
        return offset + SIZEOF_SHORT;
    }
    /**
     * Put an int value out to the specified byte array position.
     *
     * @param bytes  the byte array
     * @param offset position in the array
     * @param val    int to write out
     * @return incremented offset
     * @throws IllegalArgumentException if the byte array given doesn't have
     *                                  enough room at the offset specified.
     */
    public static int putInt(byte[] bytes, int offset, int val) {
        if (bytes.length - offset < SIZEOF_INT) {
            throw new IllegalArgumentException("Not enough room to put an int at"
                                                       + " offset " + offset + " in a " + bytes.length + " byte array");
        }
        for (int i = offset + 3; i > offset; i--) {
            bytes[i] = (byte) val;
            val >>>= 8;
        }
        bytes[offset] = (byte) val;
        return offset + SIZEOF_INT;
    }

    private static boolean isHexDigit(char c) {
        return
                (c >= 'A' && c <= 'F') ||
                        (c >= '0' && c <= '9');
    }

    /**
     * @param left  left operand
     * @param right right operand
     * @return 0 if equal, &lt; 0 if left is less than right, etc.
     */
    public static int compareTo(final byte[] left, final byte[] right) {
        return compareTo(left, 0, left.length, right, 0, right.length);
    }

    /**
     * Lexographically compare two arrays.
     *
     * @param buffer1 left operand
     * @param buffer2 right operand
     * @param offset1 Where to start comparing in the left buffer
     * @param offset2 Where to start comparing in the right buffer
     * @param length1 How much to compare from the left buffer
     * @param length2 How much to compare from the right buffer
     * @return 0 if equal, &lt; 0 if left is less than right, etc.
     */
    public static int compareTo(byte[] buffer1, int offset1, int length1,
                                byte[] buffer2, int offset2, int length2) {
        // Bring WritableComparator code local
        int end1 = offset1 + length1;
        int end2 = offset2 + length2;
        for (int i = offset1, j = offset2; i < end1 && j < end2; i++, j++) {
            int a = (buffer1[i] & 0xff);
            int b = (buffer2[j] & 0xff);
            if (a != b) {
                return a - b;
            }
        }
        return length1 - length2;
    }

    /**
     * @param left  left operand
     * @param right right operand
     * @return True if equal
     */
    public static boolean equals(final byte[] left, final byte[] right) {
        // Could use Arrays.equals?
        //noinspection SimplifiableConditionalExpression
        if (left == null && right == null) {
            return true;
        }
        return (left == null || right == null || (left.length != right.length)
                ? false : compareTo(left, right) == 0);
    }

    /**
     * Return true if the byte array on the right is a prefix of the byte
     * array on the left.
     *
     * @param bytes  byte[]
     * @param prefix byte[]
     * @return boolean
     */
    public static boolean startsWith(byte[] bytes, byte[] prefix) {
        return bytes != null && prefix != null &&
                bytes.length >= prefix.length &&
                compareTo(bytes, 0, prefix.length, prefix, 0, prefix.length) == 0;
    }


    /**
     * @param a lower half
     * @param b upper half
     * @return New array that has a in lower half and b in upper half.
     */
    public static byte[] add(final byte[] a, final byte[] b) {
        return add(a, b, new byte[0]);
    }

    /**
     * @param a first third
     * @param b second third
     * @param c third third
     * @return New array made from a, b and c
     */
    public static byte[] add(final byte[] a, final byte[] b, final byte[] c) {
        byte[] result = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        System.arraycopy(c, 0, result, a.length + b.length, c.length);
        return result;
    }

    /**
     * @param a      array
     * @param length amount of bytes to grab
     * @return First <code>length</code> bytes from <code>a</code>
     */
    public static byte[] head(final byte[] a, final int length) {
        if (a.length < length) {
            return null;
        }
        byte[] result = new byte[length];
        System.arraycopy(a, 0, result, 0, length);
        return result;
    }

    /**
     * @param a      array
     * @param length amount of bytes to snarf
     * @return Last <code>length</code> bytes from <code>a</code>
     */
    public static byte[] tail(final byte[] a, final int length) {
        if (a.length < length) {
            return null;
        }
        byte[] result = new byte[length];
        System.arraycopy(a, a.length - length, result, 0, length);
        return result;
    }

    /**
     * @param a      array
     * @param length new array size
     * @return Value in <code>a</code> plus <code>length</code> prepended 0 bytes
     */
    public static byte[] padHead(final byte[] a, final int length) {
        byte[] padding = new byte[length];
        for (int i = 0; i < length; i++) {
            padding[i] = 0;
        }
        return add(padding, a);
    }

    /**
     * @param a      array
     * @param length new array size
     * @return Value in <code>a</code> plus <code>length</code> appended 0 bytes
     */
    public static byte[] padTail(final byte[] a, final int length) {
        byte[] padding = new byte[length];
        for (int i = 0; i < length; i++) {
            padding[i] = 0;
        }
        return add(a, padding);
    }

    /**
     * Split passed range.  Expensive operation relatively.  Uses BigInteger math.
     * Useful splitting ranges for MapReduce jobs.
     *
     * @param a   Beginning of range
     * @param b   End of range
     * @param num Number of times to split range.  Pass 1 if you want to split
     *            the range in two; i.e. one split.
     * @return Array of dividing values
     */
    public static byte[][] split(final byte[] a, final byte[] b, final int num) {
        byte[][] ret = new byte[num + 2][];
        int i = 0;
        Iterable<byte[]> iter = iterateOnSplits(a, b, num);
        if (iter == null) {
            return null;
        }
        for (byte[] elem : iter) {
            ret[i++] = elem;
        }
        return ret;
    }

    public static String toHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        } else {
            return Hex.encodeHexString(data);
        }
    }
    /**
     * Takes a ASCII digit in the range A-F0-9 and returns
     * the corresponding integer/ordinal value.
     *
     * @param ch The hex digit.
     * @return The converted hex value as a byte.
     */
    public static byte toBinaryFromHex(byte ch) {
        if (ch >= 'A' && ch <= 'F') {
            return (byte) ((byte) 10 + (byte) (ch - 'A'));
        }
        // else
        return (byte) (ch - '0');
    }

    public static byte[] toBytesBinary(String in) {
        // this may be bigger than we need, but lets be safe.
        byte[] b = new byte[in.length()];
        int size = 0;
        for (int i = 0; i < in.length(); ++i) {
            char ch = in.charAt(i);
            if (ch == '\\') {
                // begin hex escape:
                char next = in.charAt(i + 1);
                if (next != 'x') {
                    // invalid escape sequence, ignore this one.
                    b[size++] = (byte) ch;
                    continue;
                }
                // ok, take next 2 hex digits.
                char hd1 = in.charAt(i + 2);
                char hd2 = in.charAt(i + 3);

                // they need to be A-F0-9:
                if (!isHexDigit(hd1) ||
                        !isHexDigit(hd2)) {
                    // bogus escape code, ignore:
                    continue;
                }
                // turn hex ASCII digit -> number
                byte d = (byte) ((toBinaryFromHex((byte) hd1) << 4) + toBinaryFromHex((byte) hd2));

                b[size++] = d;
                i += 3; // skip 3
            } else {
                b[size++] = (byte) ch;
            }
        }
        // resize:
        byte[] b2 = new byte[size];
        System.arraycopy(b, 0, b2, 0, size);
        return b2;
    }

    public static byte[] toBytes(int n) {
        byte[] b = new byte[]{(byte) (n >> 24 & 255), (byte) (n >> 16 & 255), (byte) (n >> 8 & 255),
                (byte) (n & 255)};
        return b;
    }

    public static byte[] toBytes(String str) {
        return toBytes(str, "utf-8");
    }

    public static byte[] toBytes(String str, String charset) {
        if (isEmpty(str)) {
            return new byte[0];
        } else {
            try {
                return str.getBytes(charset);
            } catch (Exception var3) {
                var3.printStackTrace();
                return new byte[0];
            }
        }
    }

    public static byte[] toBytes(String str, Charset charset) {
        if (isEmpty(str)) {
            return new byte[0];
        } else {
            try {
                return str.getBytes(charset);
            } catch (Exception var3) {
                var3.printStackTrace();
                return new byte[0];
            }
        }
    }

    /**
     * 快速判断是否是空串
     *
     * @param str 文本
     * @return true or false
     */
    public static boolean isEmpty(Object str) {
        return (str == null || "".equals(str.toString().trim()));
    }

    public static String toString(byte[] bytes) {
        if (bytes == null) {
            return "";
        } else {
            try {
                return new String(bytes, "utf-8");
            } catch (UnsupportedEncodingException var2) {
                var2.printStackTrace();
                return "";
            }
        }
    }
    public static String toString(final byte[] b, Charset charset) {
        if (b == null) {
            return null;
        }
        return new String(b, charset);
    }
    /**
     * Joins two byte arrays together using a separator.
     *
     * @param b1  The first byte array.
     * @param sep The separator to use.
     * @param b2  The second byte array.
     * @return string
     */
    public static String toString(final byte[] b1,
                                  String sep,
                                  final byte[] b2) {
        return toString(b1, 0, b1.length) + sep + toString(b2, 0, b2.length);
    }

    /**
     * This method will convert utf8 encoded bytes into a string. If
     * an UnsupportedEncodingException occurs, this method will eat it
     * and return null instead.
     *
     * @param b   Presumed UTF-8 encoded byte array.
     * @param off offset into array
     * @param len length of utf-8 sequence
     * @return String made from <code>b</code> or null
     */
    public static String toString(final byte[] b, int off, int len) {
        if (b == null) {
            return null;
        }
        if (len == 0) {
            return "";
        }
        try {
            return new String(b, off, len, "utf-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * Write a printable representation of a byte array.
     *
     * @param b byte array
     * @return string
     * @see #toStringBinary(byte[], int, int)
     */
    public static String toStringBinary(final byte[] b) {
        return toStringBinary(b, 0, b.length);
    }

    /**
     * Write a printable representation of a byte array. Non-printable
     * characters are hex escaped in the format \\x%02X, eg:
     * \x00 \x05 etc
     *
     * @param b   array to write out
     * @param off offset to start at
     * @param len length to write
     * @return string output
     */
    public static String toStringBinary(final byte[] b, int off, int len) {
        StringBuilder result = new StringBuilder();
        try {
            String first = new String(b, off, len, "ISO-8859-1");
            for (int i = 0; i < first.length(); ++i) {
                int ch = first.charAt(i) & 0xFF;
                if ((ch >= '0' && ch <= '9')
                        || (ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || " `~!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?".indexOf(ch) >= 0) {
                    result.append(first.charAt(i));
                } else {
                    result.append(String.format("\\x%02X", ch));
                }
            }
        } catch (UnsupportedEncodingException e) {
        }
        return result.toString();
    }

    public static byte[] toBytes(long n) {
        byte[] b = new byte[]{(byte) ((int) (n >> 56 & 255L)), (byte) ((int) (n >> 48 & 255L)),
                (byte) ((int) (n >> 40 & 255L)), (byte) ((int) (n >> 32 & 255L)),
                (byte) ((int) (n >> 24 & 255L)), (byte) ((int) (n >> 16 & 255L)),
                (byte) ((int) (n >> 8 & 255L)), (byte) ((int) (n & 255L))};
        return b;
    }

    public static void toBytes(long n, byte[] array, int offset) {
        array[7 + offset] = (byte) ((int) (n & 255L));
        array[6 + offset] = (byte) ((int) (n >> 8 & 255L));
        array[5 + offset] = (byte) ((int) (n >> 16 & 255L));
        array[4 + offset] = (byte) ((int) (n >> 24 & 255L));
        array[3 + offset] = (byte) ((int) (n >> 32 & 255L));
        array[2 + offset] = (byte) ((int) (n >> 40 & 255L));
        array[1 + offset] = (byte) ((int) (n >> 48 & 255L));
        array[0 + offset] = (byte) ((int) (n >> 56 & 255L));
    }

    public static long toLong(byte[] array) {
        return ((long) array[0] & 255L) << 56 | ((long) array[1] & 255L) << 48
                | ((long) array[2] & 255L) << 40 | ((long) array[3] & 255L) << 32
                | ((long) array[4] & 255L) << 24 | ((long) array[5] & 255L) << 16
                | ((long) array[6] & 255L) << 8 | ((long) array[7] & 255L) << 0;
    }

    public static long toLong(byte[] array, int offset) {
        return ((long) array[offset + 0] & 255L) << 56 | ((long) array[offset + 1] & 255L) << 48
                | ((long) array[offset + 2] & 255L) << 40 | ((long) array[offset + 3] & 255L) << 32
                | ((long) array[offset + 4] & 255L) << 24 | ((long) array[offset + 5] & 255L) << 16
                | ((long) array[offset + 6] & 255L) << 8 | ((long) array[offset + 7] & 255L) << 0;
    }

    public static void toBytes(int n, byte[] array, int offset) {
        array[3 + offset] = (byte) (n & 255);
        array[2 + offset] = (byte) (n >> 8 & 255);
        array[1 + offset] = (byte) (n >> 16 & 255);
        array[offset] = (byte) (n >> 24 & 255);
    }

    public static int toInt(byte[] b) {
        return b[3] & 255 | (b[2] & 255) << 8 | (b[1] & 255) << 16 | (b[0] & 255) << 24;
    }

    public static int toInt(byte[] b, int offset) {
        return b[offset + 3] & 255 | (b[offset + 2] & 255) << 8 | (b[offset + 1] & 255) << 16
                | (b[offset] & 255) << 24;
    }

    public static byte[] toBytes(short n) {
        byte[] b = new byte[]{(byte) (n >> 8 & 255), (byte) (n & 255)};
        return b;
    }

    public static void toBytes(short n, byte[] array, int offset) {
        array[offset + 1] = (byte) (n & 255);
        array[offset] = (byte) (n >> 8 & 255);
    }

    public static short toShort(byte[] b) {
        return (short) (b[1] & 255 | (b[0] & 255) << 8);
    }

    public static short toShort(byte[] b, int offset) {
        return (short) (b[offset + 1] & 255 | (b[offset] & 255) << 8);
    }

    public static byte[] uintToBytes(long n) {
        byte[] b = new byte[]{(byte) ((int) (n >> 24 & 255L)), (byte) ((int) (n >> 16 & 255L)),
                (byte) ((int) (n >> 8 & 255L)), (byte) ((int) (n & 255L))};
        return b;
    }

    public static void uintToBytes(long n, byte[] array, int offset) {
        array[3 + offset] = (byte) ((int) n);
        array[2 + offset] = (byte) ((int) (n >> 8 & 255L));
        array[1 + offset] = (byte) ((int) (n >> 16 & 255L));
        array[offset] = (byte) ((int) (n >> 24 & 255L));
    }

    public static long bytesToUint(byte[] array) {
        return (long) (array[3] & 255) | (long) (array[2] & 255) << 8
                | (long) (array[1] & 255) << 16 | (long) (array[0] & 255) << 24;
    }

    public static long bytesToUint(byte[] array, int offset) {
        return (long) (array[offset + 3] & 255) | (long) (array[offset + 2] & 255) << 8
                | (long) (array[offset + 1] & 255) << 16 | (long) (array[offset] & 255) << 24;
    }

    public static byte[] ushortToBytes(int n) {
        byte[] b = new byte[]{(byte) (n >> 8 & 255), (byte) (n & 255)};
        return b;
    }

    public static void ushortToBytes(int n, byte[] array, int offset) {
        array[offset + 1] = (byte) (n & 255);
        array[offset] = (byte) (n >> 8 & 255);
    }

    public static int bytesToUshort(byte[] b) {
        return b[1] & 255 | (b[0] & 255) << 8;
    }

    public static int bytesToUshort(byte[] b, int offset) {
        return b[offset + 1] & 255 | (b[offset] & 255) << 8;
    }

    public static byte[] ubyteToBytes(int n) {
        byte[] b = new byte[]{(byte) (n & 255)};
        return b;
    }

    public static void ubyteToBytes(int n, byte[] array, int offset) {
        array[0] = (byte) (n & 255);
    }

    public static int bytesToUbyte(byte[] array) {
        return array[0] & 255;
    }

    public static int bytesToUbyte(byte[] array, int offset) {
        return array[offset] & 255;
    }

    private static byte[] toByteArray(InputStream input) throws IOException {
        if (input != null && input.available() != 0) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            boolean n = false;

            int n1;
            while (-1 != (n1 = input.read(buffer))) {
                baos.write(buffer, 0, n1);
            }

            return baos.toByteArray();
        } else {
            return null;
        }
    }
    /**
     * Iterate over keys within the passed inclusive range.
     *
     * @param a   array
     * @param b   array
     * @param num int
     * @return Iterable
     */
    public static Iterable<byte[]> iterateOnSplits(
            final byte[] a, final byte[] b, final int num) {
        byte[] aPadded;
        byte[] bPadded;
        if (a.length < b.length) {
            aPadded = padTail(a, b.length - a.length);
            bPadded = b;
        } else if (b.length < a.length) {
            aPadded = a;
            bPadded = padTail(b, a.length - b.length);
        } else {
            aPadded = a;
            bPadded = b;
        }
        if (compareTo(aPadded, bPadded) >= 0) {
            throw new IllegalArgumentException("b <= a");
        }
        if (num <= 0) {
            throw new IllegalArgumentException("num cannot be < 0");
        }
        byte[] prependHeader = {1, 0};
        final BigInteger startBI = new BigInteger(add(prependHeader, aPadded));
        final BigInteger stopBI = new BigInteger(add(prependHeader, bPadded));
        final BigInteger diffBI = stopBI.subtract(startBI);
        final BigInteger splitsBI = BigInteger.valueOf(num + 1);
        if (diffBI.compareTo(splitsBI) < 0) {
            return null;
        }
        final BigInteger intervalBI;
        try {
            intervalBI = diffBI.divide(splitsBI);
        } catch (Exception e) {
            return null;
        }

        final Iterator<byte[]> iterator = new Iterator<byte[]>() {
            private int i = -1;

            @Override
            public boolean hasNext() {
                return i < num + 1;
            }

            @Override
            public byte[] next() {
                i++;
                if (i == 0) {
                    return a;
                }
                if (i == num + 1) {
                    return b;
                }

                BigInteger curBI = startBI.add(intervalBI.multiply(BigInteger.valueOf(i)));
                byte[] padded = curBI.toByteArray();
                if (padded[1] == 0) {
                    padded = tail(padded, padded.length - 2);
                } else {
                    padded = tail(padded, padded.length - 1);
                }
                return padded;
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException();
            }

        };

        return new Iterable<byte[]>() {
            @Override
            public Iterator<byte[]> iterator() {
                return iterator;
            }
        };
    }

    /**
     * @param t operands
     * @return Array of byte arrays made from passed array of Text
     */
    public static byte[][] toByteArrays(final String[] t) {
        byte[][] result = new byte[t.length][];
        for (int i = 0; i < t.length; i++) {
            result[i] = toBytes(t[i]);
        }
        return result;
    }

    /**
     * @param column operand
     * @return A byte array of a byte array where first and only entry is
     * <code>column</code>
     */
    public static byte[][] toByteArrays(final String column) {
        return toByteArrays(toBytes(column));
    }

    /**
     * @param column operand
     * @return A byte array of a byte array where first and only entry is
     * <code>column</code>
     */
    public static byte[][] toByteArrays(final byte[] column) {
        byte[][] result = new byte[1][];
        result[0] = column;
        return result;
    }

    public static String newStringUTF8(byte[] data) {
        return newString(data, "UTF-8");
    }

    public static String newStringUTF8(byte[] data, int offset, int length) {
        return newString(data, offset, length, "UTF-8");
    }

    public static String newString(byte[] data, String charsetName) {
        return newString(data, 0, data.length, charsetName);
    }

    public static String newString(byte[] data, int offset, int length, String
            charsetName) {
        try {
            if (data == null || data.length == 0)
                return "";

            return new String(data, offset, length, charsetName);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "";
        }
    }
}
