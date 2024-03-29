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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.IntegerUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Concatenation Key Derivation Function (KDF). This class is thread-safe.
 *
 * <p>See NIST.800-56A.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class ConcatKDF {


    /**
     * The JCA name of the hash algorithm.
     */
    private final String jcaHashAlg;


    /**
     * Creates a new concatenation Key Derivation Function (KDF) with the
     * specified hash algorithm.
     *
     * @param jcaHashAlg The JCA name of the hash algorithm. Must be
     *                   supported and not {@code null}.
     */
    public ConcatKDF(String jcaHashAlg) {

        if (jcaHashAlg == null) {
            throw new IllegalArgumentException("The JCA hash algorithm must not be null");
        }

        this.jcaHashAlg = jcaHashAlg;
    }


    /**
     * Returns the JCA name of the hash algorithm.
     *
     * @return The JCA name of the hash algorithm.
     */
    public String getHashAlgorithm() {

        return jcaHashAlg;
    }

    /**
     * Derives a key from the specified inputs.
     *
     * @param sharedSecret  The shared secret. Must not be {@code null}.
     * @param keyLengthBits The length of the key to derive, in bits.
     * @param otherInfo     Other info, {@code null} if not specified.
     * @return The derived key, with algorithm set to "AES".
     */
    public SecretKey deriveKey(SecretKey sharedSecret,
                               int keyLengthBits,
                               byte[] otherInfo) {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        MessageDigest md = getMessageDigest();

        for (int i = 1; i <= computeDigestCycles(ByteUtils.safeBitLength(md.getDigestLength()), keyLengthBits); i++) {

            byte[] counterBytes = IntegerUtils.toBytes(i);

            md.update(counterBytes);
            md.update(sharedSecret.getEncoded());

            if (otherInfo != null) {
                md.update(otherInfo);
            }

            try {
                baos.write(md.digest());
            } catch (IOException e) {
                throw new JOSEException("Couldn't write derived key: " + e.getMessage(), e);
            }
        }

        byte[] derivedKeyMaterial = baos.toByteArray();

        int keyLengthBytes = ByteUtils.byteLength(keyLengthBits);

        if (derivedKeyMaterial.length == keyLengthBytes) {
            // Return immediately
            return new SecretKeySpec(derivedKeyMaterial, "AES");
        }

        return new SecretKeySpec(ByteUtils.subArray(derivedKeyMaterial, 0, keyLengthBytes), "AES");
    }


    /**
     * Derives a key from the specified inputs.
     *
     * @param sharedSecret The shared secret. Must not be {@code null}.
     * @param keyLength    The length of the key to derive, in bits.
     * @param algID        The algorithm identifier, {@code null} if not
     *                     specified.
     * @param partyUInfo   The partyUInfo, {@code null} if not specified.
     * @param partyVInfo   The partyVInfo {@code null} if not specified.
     * @param suppPubInfo  The suppPubInfo, {@code null} if not specified.
     * @param suppPrivInfo The suppPrivInfo, {@code null} if not specified.
     * @return The derived key, with algorithm set to "AES".
     */
    public SecretKey deriveKey(SecretKey sharedSecret,
                               int keyLength,
                               byte[] algID,
                               byte[] partyUInfo,
                               byte[] partyVInfo,
                               byte[] suppPubInfo,
                               byte[] suppPrivInfo) {

        byte[] otherInfo = composeOtherInfo(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);

        return deriveKey(sharedSecret, keyLength, otherInfo);
    }


    /**
     * Composes the other info as {@code algID || partyUInfo || partyVInfo
     * || suppPubInfo || suppPrivInfo}.
     *
     * @param algID        The algorithm identifier, {@code null} if not
     *                     specified.
     * @param partyUInfo   The partyUInfo, {@code null} if not specified.
     * @param partyVInfo   The partyVInfo {@code null} if not specified.
     * @param suppPubInfo  The suppPubInfo, {@code null} if not specified.
     * @param suppPrivInfo The suppPrivInfo, {@code null} if not specified.
     * @return The resulting other info.
     */
    public static byte[] composeOtherInfo(byte[] algID,
                                          byte[] partyUInfo,
                                          byte[] partyVInfo,
                                          byte[] suppPubInfo,
                                          byte[] suppPrivInfo) {

        return ByteUtils.concat(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
    }

    /**
     * Derives a key from the specified inputs.
     *
     * @param sharedSecret The shared secret. Must not be {@code null}.
     * @param keyLength    The length of the key to derive, in bits.
     * @param algID        The algorithm identifier, {@code null} if not
     *                     specified.
     * @param partyUInfo   The partyUInfo, {@code null} if not specified.
     * @param partyVInfo   The partyVInfo {@code null} if not specified.
     * @param suppPubInfo  The suppPubInfo, {@code null} if not specified.
     * @param suppPrivInfo The suppPrivInfo, {@code null} if not specified.
     * @return The derived key, with algorithm set to "AES".
     * @throws JOSEException If the key derivation failed.
     */
    public SecretKey deriveKey(SecretKey sharedSecret,
                               int keyLength,
                               byte[] algID,
                               byte[] partyUInfo,
                               byte[] partyVInfo,
                               byte[] suppPubInfo,
                               byte[] suppPrivInfo,
                               byte[] tag)
            throws JOSEException {

        final byte[] otherInfo = composeOtherInfo(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo, tag);

        return deriveKey(sharedSecret, keyLength, otherInfo);
    }


    /**
     * Composes the other info as {@code algID || partyUInfo || partyVInfo
     * || suppPubInfo || suppPrivInfo || tag}.
     *
     * @param algID        The algorithm identifier, {@code null} if not
     *                     specified.
     * @param partyUInfo   The partyUInfo, {@code null} if not specified.
     * @param partyVInfo   The partyVInfo {@code null} if not specified.
     * @param suppPubInfo  The suppPubInfo, {@code null} if not specified.
     * @param suppPrivInfo The suppPrivInfo, {@code null} if not specified.
     * @param tag          The cctag, {@code null} if not specified.
     * @return The resulting other info.
     */
    public static byte[] composeOtherInfo(byte[] algID,
                                          byte[] partyUInfo,
                                          byte[] partyVInfo,
                                          byte[] suppPubInfo,
                                          byte[] suppPrivInfo,
                                          byte[] tag) {

        return ByteUtils.concat(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo, tag);
    }

    /**
     * Returns a message digest instance for the configured
     * {@link #jcaHashAlg hash algorithm}.
     *
     * @return The message digest instance.
     */
    private MessageDigest getMessageDigest() {

        try {
            return MessageDigest.getInstance(jcaHashAlg, BouncyCastleProviderSingleton.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't get message digest for KDF: " + e.getMessage(), e);
        }
    }


    /**
     * Computes the required digest (hashing) cycles for the specified
     * message digest length and derived key length.
     *
     * @param digestLengthBits The length of the message digest, in bits.
     * @param keyLengthBits    The length of the derived key, in bits.
     * @return The digest cycles.
     */
    public static int computeDigestCycles(int digestLengthBits, int keyLengthBits) {

        // return the ceiling of keyLength / digestLength

        return (keyLengthBits + digestLengthBits - 1) / digestLengthBits;
    }


    /**
     * Encodes no / empty data as an empty byte array.
     *
     * @return The encoded data.
     */
    public static byte[] encodeNoData() {

        return new byte[0];
    }


    /**
     * Encodes the specified integer data as a four byte array.
     *
     * @param data The integer data to encode.
     * @return The encoded data.
     */
    public static byte[] encodeIntData(int data) {

        return IntegerUtils.toBytes(data);
    }


    /**
     * Encodes the specified string data as {@code data.length || data}.
     *
     * @param data The string data, UTF-8 encoded. May be {@code null}.
     * @return The encoded data.
     */
    public static byte[] encodeStringData(String data) {

        byte[] bytes = data != null ? data.getBytes(UTF_8) : null;
        return encodeDataWithLength(bytes);
    }


    /**
     * Encodes the specified data as {@code data.length || data}.
     *
     * @param data The data to encode, may be {@code null}.
     * @return The encoded data.
     */
    public static byte[] encodeDataWithLength(byte[] data) {

        byte[] bytes = data != null ? data : new byte[0];
        byte[] length = IntegerUtils.toBytes(bytes.length);
        return ByteUtils.concat(length, bytes);
    }


    /**
     * Encodes the specified BASE64URL encoded data
     * {@code data.length || data}.
     *
     * @param data The data to encode, may be {@code null}.
     * @return The encoded data.
     */
    public static byte[] encodeDataWithLength(Base64URLValue data) {

        byte[] bytes = data != null ? data.decode() : null;
        return encodeDataWithLength(bytes);
    }
}

