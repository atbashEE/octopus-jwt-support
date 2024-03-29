/*
 * Copyright 2017-2022 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.nimbus.util;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Byte utilities.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class ByteUtils {


    /**
     * Concatenates the specified byte arrays.
     *
     * @param byteArrays The byte arrays to concatenate, may be
     *                   {@code null}.
     * @return The resulting byte array.
     */
    public static byte[] concat(byte[]... byteArrays) {

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (byte[] bytes : byteArrays) {

                if (bytes == null) {
                    continue; // skip
                }

                baos.write(bytes);
            }
            return baos.toByteArray();

        } catch (IOException e) {
            // Should never happen
            throw new IllegalStateException(e.getMessage(), e);
        }
    }


    /**
     * Returns a portion of the specified byte array.
     *
     * @param byteArray  The byte array. Must not be {@code null}.
     * @param beginIndex The beginning index, inclusive. Must be zero or
     *                   positive.
     * @param length     The length. Must be zero or positive.
     * @return The byte array portion.
     */
    public static byte[] subArray(byte[] byteArray, int beginIndex, int length) {

        byte[] subArray = new byte[length];
        System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
        return subArray;
    }


    /**
     * Returns the bit length of the specified byte length.
     *
     * @param byteLength The byte length.
     * @return The bit length.
     */
    public static int bitLength(int byteLength) {

        return byteLength * 8;
    }


    /**
     * Returns the bit length of the specified byte length, preventing
     * integer overflow.
     *
     * @param byteLength The byte length.
     * @return The bit length.
     * @throws IntegerOverflowException On a integer overflow.
     */
    public static int safeBitLength(int byteLength)
            throws IntegerOverflowException {

        long longResult = (long) byteLength * (long) 8;
        if ((long) ((int) longResult) != longResult) {
            throw new IntegerOverflowException();
        } else {
            return (int) longResult;
        }
    }


    /**
     * Returns the byte length of the specified byte array.
     *
     * @param byteArray The byte array. May be {@code null}.
     * @return The bite length, zero if the array is {@code null}.
     */
    public static int bitLength(byte[] byteArray) {

        if (byteArray == null) {
            return 0;
        } else {
            return bitLength(byteArray.length);
        }
    }


    /**
     * Returns the byte length of the specified byte array, preventing
     * integer overflow.
     *
     * @param byteArray The byte array. May be {@code null}.
     * @return The bite length, zero if the array is {@code null}.
     * @throws IntegerOverflowException On a integer overflow.
     */
    public static int safeBitLength(byte[] byteArray)
            throws IntegerOverflowException {

        if (byteArray == null) {
            return 0;
        } else {
            return safeBitLength(byteArray.length);
        }
    }


    /**
     * Returns the byte length of the specified bit length.
     *
     * @param bitLength The bit length.
     * @return The byte byte length.
     */
    public static int byteLength(int bitLength) {

        return bitLength / 8;
    }

    /**
     * Read all bytes from the inputstream. The stream is closed after it is fully read.
     *
     * @param inputStream The stream to read from
     * @return The byte array contained in the stream.
     * @throws IOException When exception occurred during reading of the Stream.
     */
    public static byte[] readAllBytes(InputStream inputStream) throws IOException {
        final int bufLen = 4 * 0x400; // 4KB
        byte[] buf = new byte[bufLen];
        int readLen;

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            while ((readLen = inputStream.read(buf, 0, bufLen)) != -1) {
                outputStream.write(buf, 0, readLen);
            }

            return outputStream.toByteArray();
        } finally {
            inputStream.close();
        }
    }

    /**
     * Returns {@code true} if the specified byte array is zero filled.
     *
     * @param byteArray the byte array. Must not be {@code null}.
     * @return {@code true} if zero filled, else {@code false}.
     */
    public static boolean isZeroFilled(byte[] byteArray) {

        for (final byte b : byteArray) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
