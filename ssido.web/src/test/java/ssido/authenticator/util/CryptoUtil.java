/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package ssido.authenticator.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author ITON Solutions
 */
public class CryptoUtil {
    /**
     * Returns the values from each provided array combined into a single array. For example, {@code
     * concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array {@code {a, b, c}}.
     *
     * @param arrays zero or more {@code byte} arrays
     * @return a single array containing all the values from the source arrays, in order
     */
    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }
    
    public static byte[] fromHex(String data) {
        byte[] result = new byte[data.length() / 2];

        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            result[i] = Integer.valueOf(data.substring(index, index + 2), 0x10).byteValue();
        }
        return result;
    }
    
    /**
     * @param bytes
     * @return 
     */
    public static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
    
     public static byte[] sha256(byte[] bytes){
        try {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
        }catch(NoSuchAlgorithmException e){
            return new byte[0];
        }
    }
     
     public static byte[] encodeUint16(short value) {
        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putShort(value);
        buffer.rewind();
        return buffer.array();
    }
     
     public static byte[] encodeUint32(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(value);
        buffer.rewind();
        return buffer.array();
    }
     
    /**
     * Read 4 bytes as a big endian unsigned 32-bit integer.
     * <p>
     * Result is of type Long because Java don't have unsigned types.
     *
     * @param bytes
     * @return A value between 0 and 2^32 - 1, inclusive.
     */
    public static int getUint32(byte[] bytes) {
        if (bytes.length == 4) {
            // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
            return ByteBuffer.wrap(new byte[] {bytes[0], bytes[1], bytes[2], bytes[3]})
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();
        } else {
            throw new IllegalArgumentException("Argument must be 4 bytes, was: " + bytes.length);
        }
    }
}
