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


import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.Base64;
import java.util.UUID;


/**
 * X.509 certificate utilities.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public final class X509CertUtils {


    /**
     * The PEM start marker.
     */
    private static final String PEM_BEGIN_MARKER = "-----BEGIN CERTIFICATE-----";


    /**
     * The PEM end marker.
     */
    private static final String PEM_END_MARKER = "-----END CERTIFICATE-----";


    /**
     * Parses a DER-encoded X.509 certificate.
     *
     * @param derEncodedCert The DER-encoded X.509 certificate, as a byte
     *                       array. May be {@code null}.
     * @return The X.509 certificate, {@code null} if not specified or
     * parsing failed.
     */
    public static X509Certificate parse(byte[] derEncodedCert) {

        try {
            return parseWithException(derEncodedCert);
        } catch (CertificateException e) {
            return null;
        }
    }


    /**
     * Parses a DER-encoded X.509 certificate with exception handling.
     *
     * @param derEncodedCert The DER-encoded X.509 certificate, as a byte
     *                       array. Empty or {@code null} if not specified.
     * @return The X.509 certificate, {@code null} if not specified.
     * @throws CertificateException If parsing failed.
     */
    public static X509Certificate parseWithException(byte[] derEncodedCert)
            throws CertificateException {

        if (derEncodedCert == null || derEncodedCert.length == 0) {
            return null;
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(derEncodedCert));

        if (!(cert instanceof X509Certificate)) {
            throw new CertificateException("Not a X.509 certificate: " + cert.getType());
        }

        return (X509Certificate) cert;
    }


    /**
     * Parses a PEM-encoded X.509 certificate.
     *
     * @param pemEncodedCert The PEM-encoded X.509 certificate, as a
     *                       string. Empty or {@code null} if not
     *                       specified.
     * @return The X.509 certificate, {@code null} if parsing failed.
     */
    public static X509Certificate parse(String pemEncodedCert) {

        if (pemEncodedCert == null || pemEncodedCert.isEmpty()) {
            return null;
        }

        int markerStart = pemEncodedCert.indexOf(PEM_BEGIN_MARKER);

        if (markerStart < 0) {
            return null;
        }

        String buf = pemEncodedCert.substring(markerStart + PEM_BEGIN_MARKER.length());

        int markerEnd = buf.indexOf(PEM_END_MARKER);

        if (markerEnd < 0) {
            return null;
        }

        buf = buf.substring(0, markerEnd);

        buf = buf.replaceAll("\\s", "");

        return parse(new Base64Value(buf).decode());
    }


    /**
     * Parses a PEM-encoded X.509 certificate with exception handling.
     *
     * @param pemEncodedCert The PEM-encoded X.509 certificate, as a
     *                       string. Empty or {@code null} if not
     *                       specified.
     * @return The X.509 certificate, {@code null} if parsing failed.
     */
    public static X509Certificate parseWithException(String pemEncodedCert)
            throws CertificateException {

        if (pemEncodedCert == null || pemEncodedCert.isEmpty()) {
            return null;
        }

        int markerStart = pemEncodedCert.indexOf(PEM_BEGIN_MARKER);

        if (markerStart < 0) {
            throw new CertificateException("PEM begin marker not found");
        }

        String buf = pemEncodedCert.substring(markerStart + PEM_BEGIN_MARKER.length());

        int markerEnd = buf.indexOf(PEM_END_MARKER);

        if (markerEnd < 0) {
            throw new CertificateException("PEM end marker not found");
        }

        buf = buf.substring(0, markerEnd);

        buf = buf.replaceAll("\\s", "");

        return parseWithException(new Base64Value(buf).decode());
    }


    /**
     * Returns the specified X.509 certificate as PEM-encoded string.
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return The PEM-encoded X.509 certificate, {@code null} if encoding
     * failed.
     */
    public static String toPEMString(X509Certificate cert) {

        return toPEMString(cert, true);
    }


    /**
     * Returns the specified X.509 certificate as PEM-encoded string.
     *
     * @param cert           The X.509 certificate. Must not be
     *                       {@code null}.
     * @param withLineBreaks {@code false} to suppress line breaks.
     * @return The PEM-encoded X.509 certificate, {@code null} if encoding
     * failed.
     */
    public static String toPEMString(X509Certificate cert, boolean withLineBreaks) {

        StringBuilder sb = new StringBuilder();
        sb.append(PEM_BEGIN_MARKER);

        if (withLineBreaks)
            sb.append('\n');

        try {
            sb.append(Base64.getEncoder().encodeToString(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
            return null;
        }

        if (withLineBreaks)
            sb.append('\n');

        sb.append(PEM_END_MARKER);
        return sb.toString();
    }


    /**
     * Computes the X.509 certificate SHA-256 thumbprint ({@code x5t#S256}).
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return The SHA-256 thumbprint, BASE64URL-encoded, {@code null} if
     * a certificate encoding exception is encountered.
     */
    public static Base64URLValue computeSHA256Thumbprint(X509Certificate cert) {

        try {
            byte[] derEncodedCert = cert.getEncoded();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return Base64URLValue.encode(sha256.digest(derEncodedCert));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            return null;
        }
    }

    /**
     * Stores a private key with its associated X.509 certificate in a
     * Java key store. The name (alias) for the stored entry is given a
     * random UUID.
     *
     * @param keyStore    The key store. Must be initialised and not
     *                    {@code null}.
     * @param privateKey  The private key. Must not be {@code null}.
     * @param keyPassword The password to protect the private key, empty
     *                    array for none. Must not be {@code null}.
     * @param cert        The X.509 certificate, its public key and the
     *                    private key should form a pair. Must not be
     *                    {@code null}.
     * @return The UUID for the stored entry.
     */
    public static UUID store(KeyStore keyStore,
                             Key privateKey,
                             char[] keyPassword,
                             X509Certificate cert)
            throws KeyStoreException {

        UUID alias = UUID.randomUUID();
        keyStore.setKeyEntry(alias.toString(), privateKey, keyPassword, new Certificate[]{cert});
        return alias;
    }

    private X509CertUtils() {
    }
}
