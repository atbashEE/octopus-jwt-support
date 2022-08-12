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


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.KeyReaderPEM;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.IOUtil;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import org.assertj.core.api.Assertions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;


/**
 * Tests the X.509 certificate utilities.
 */
public class X509CertUtilsTest {


    private static final String PEM_CERT =
            "-----BEGIN CERTIFICATE-----" +
                    "MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV" +
                    "BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow" +
                    "GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz" +
                    "LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1" +
                    "cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN" +
                    "MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0" +
                    "ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC" +
                    "AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX" +
                    "57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB" +
                    "1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL" +
                    "HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED" +
                    "pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb" +
                    "GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T" +
                    "AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/" +
                    "BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v" +
                    "Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG" +
                    "AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv" +
                    "cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k" +
                    "YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk" +
                    "ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD" +
                    "MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u" +
                    "bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG" +
                    "SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln" +
                    "2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M" +
                    "l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN" +
                    "KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP" +
                    "63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ" +
                    "X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy" +
                    "-----END CERTIFICATE-----";


    private static final String PEM_CERT_WITH_WHITESPACE =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV\n" +
                    "BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow\n" +
                    "GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz\n" +
                    "LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1\n" +
                    "cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN\n" +
                    "MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0\n" +
                    "ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
                    "AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX\n" +
                    "57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB\n" +
                    "1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL\n" +
                    "HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED\n" +
                    "pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb\n" +
                    "GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T\n" +
                    "AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/\n" +
                    "BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v\n" +
                    "Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG\n" +
                    "AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv\n" +
                    "cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k\n" +
                    "YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk\n" +
                    "ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD\n" +
                    "MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u\n" +
                    "bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG\n" +
                    "SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln\n" +
                    "2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M\n" +
                    "l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN\n" +
                    "KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP\n" +
                    "63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ\n" +
                    "X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy\n" +
                    "-----END CERTIFICATE-----\n";


    @Test
    public void testParsePEM() {

        X509Certificate cert = X509CertUtils.parse(PEM_CERT);

        Assertions.assertThat(cert.getType()).isEqualTo("X.509");
        Assertions.assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=connect2id.com,OU=Domain Control Validated");
        Assertions.assertThat(cert.getPublicKey()).isInstanceOf(RSAPublicKey.class);
    }


    @Test
    public void testParsePEMWithException()
            throws Exception {

        X509Certificate cert = X509CertUtils.parseWithException(PEM_CERT);

        Assertions.assertThat(cert.getType()).isEqualTo("X.509");
        Assertions.assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=connect2id.com,OU=Domain Control Validated");
        Assertions.assertThat(cert.getPublicKey()).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    public void testParsePEMWithException_noBeginMarker() {

        Assertions.assertThatThrownBy(() -> X509CertUtils.parseWithException(PEM_CERT.replace("-----BEGIN CERTIFICATE-----", "")))
                .isInstanceOf(CertificateException.class)
                .hasMessage("PEM begin marker not found");
    }

    @Test
    public void testParsePEMWithException_noEndMarker() {

        Assertions.assertThatThrownBy(() -> X509CertUtils.parseWithException(PEM_CERT.replace("-----END CERTIFICATE-----", "")))
                .isInstanceOf(CertificateException.class)
                .hasMessage("PEM end marker not found");

    }

    @Test
    public void testParsePEMWithException_corruptedContent() {

        Assertions.assertThatThrownBy(() -> X509CertUtils.parseWithException("-----BEGIN CERTIFICATE-----MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV-----END CERTIFICATE-----"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("Could not parse certificate: java.io.IOException: Incomplete BER/DER data");

    }

    @Test
    public void testParsePEM_withWhitespace() {

        X509Certificate cert = X509CertUtils.parse(PEM_CERT_WITH_WHITESPACE);

        Assertions.assertThat(cert.getType()).isEqualTo("X.509");
        Assertions.assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=connect2id.com,OU=Domain Control Validated");
        Assertions.assertThat(cert.getPublicKey()).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    public void testParseCertWithECKey()
            throws Exception {

        String content = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");

        X509Certificate cert = X509CertUtils.parse(content);
        Assertions.assertThat(cert).isNotNull();

        Assertions.assertThat(cert.getPublicKey()).isInstanceOf(ECPublicKey.class);

        // For definition, see rfc2459, 4.2.1.3 Key Usage
        Assertions.assertThat(cert.getKeyUsage()[0]).withFailMessage("Digital signature").isTrue();
        Assertions.assertThat(cert.getKeyUsage()[1]).withFailMessage("Non repudiation").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[2]).withFailMessage("Key encipherment").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[3]).withFailMessage("Data encipherment").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[4]).withFailMessage("Key agreement").isTrue();
        Assertions.assertThat(cert.getKeyUsage()[5]).withFailMessage("Key certificate signing").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[6]).withFailMessage("CRL signing").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[7]).withFailMessage("Decipher").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[8]).withFailMessage("Encipher").isFalse();

        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

        String ecPubKeyAlg = "1.2.840.10045.2.1";

        Assertions.assertThat(certHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId()).isEqualTo(ecPubKeyAlg);
        Assertions.assertThat(certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString()).isEqualTo(Curve.P_256.getOID());
    }

    @Test
    public void testParseCertWithRSAKey()
            throws Exception {

        String content = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");

        X509Certificate cert = X509CertUtils.parse(content);
        Assertions.assertThat(cert).isNotNull();

        Assertions.assertThat(cert.getPublicKey()).isInstanceOf(RSAPublicKey.class);

        // For definition, see rfc2459, 4.2.1.3 Key Usage
        Assertions.assertThat(cert.getKeyUsage()[0]).withFailMessage("Digital signature").isTrue();
        Assertions.assertThat(cert.getKeyUsage()[1]).withFailMessage("Non repudiation").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[2]).withFailMessage("Key encipherment").isTrue();
        Assertions.assertThat(cert.getKeyUsage()[3]).withFailMessage("Data encipherment").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[4]).withFailMessage("Key agreement").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[5]).withFailMessage("Key certificate signing").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[6]).withFailMessage("CRL signing").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[7]).withFailMessage("Decipher").isFalse();
        Assertions.assertThat(cert.getKeyUsage()[8]).withFailMessage("Encipher").isFalse();

        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

        String rsaPubKeyAlg = "1.2.840.113549.1.1.1";
        Assertions.assertThat(certHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId()).isEqualTo(rsaPubKeyAlg);
        Assertions.assertThat(certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString()).isEqualTo("NULL");
    }

    @Test
    public void testSHA256Thumbprint()
            throws Exception {

        X509Certificate cert = X509CertUtils.parse(PEM_CERT);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(cert.getEncoded());
        Assertions.assertThat(ByteUtils.bitLength(hash)).isEqualTo(256);

        Base64URLValue thumbPrint = X509CertUtils.computeSHA256Thumbprint(cert);

        Assertions.assertThat(thumbPrint).isEqualTo(Base64URLValue.encode(hash));
    }

    @Test
    public void testPEMRoundTrip() {

        X509Certificate cert = X509CertUtils.parse(PEM_CERT);
        String pemString = X509CertUtils.toPEMString(cert);
        String[] lines = pemString.split("\\n");
        Assertions.assertThat(lines[0]).isEqualTo("-----BEGIN CERTIFICATE-----");
        Assertions.assertThat(lines[2]).isEqualTo("-----END CERTIFICATE-----");
        Assertions.assertThat(lines.length).isEqualTo(3);
        Assertions.assertThat(X509CertUtils.parse(pemString).getSubjectDN()).isEqualTo(cert.getSubjectDN());
    }

    @Test
    public void testPEMRoundTrip_noLineBreaks() {

        X509Certificate cert = X509CertUtils.parse(PEM_CERT);
        String pemString = X509CertUtils.toPEMString(cert, false);
        Assertions.assertThat(pemString).isNotNull();
        Assertions.assertThat(pemString.indexOf("\n")).isEqualTo(-1);
        Assertions.assertThat(X509CertUtils.parse(pemString).getSubjectDN()).isEqualTo(cert.getSubjectDN());
    }

    @Test
    public void testStore_noPassword() throws Exception {

        KeyReaderPEM keyReaderPEM = new KeyReaderPEM();

        String content = IOUtil.readFileToString("src/test/resources/sample-pem-encoded-objects/ecprivkey.pem");
        List<AtbashKey> keys = keyReaderPEM.parseContent(content);
        Assertions.assertThat(keys).hasSize(2);
        Assertions.assertThat(keys.get(0).getSecretKeyType().getKeyType()).isEqualTo(KeyType.EC);

        AtbashKey ecPrivateKey = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys).get(0);
        AtbashKey ecPublicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys).get(0);

        content = IOUtil.readFileToString("src/test/resources/sample-pem-encoded-objects/eccert.pem");
        X509Certificate certificate = X509CertUtils.parse(content);

        // Check if the loaded certificate has public key that matches with the EC key that was loaded
        Assertions.assertThat(certificate).isNotNull();
        Assertions.assertThat(ecPublicKey.getKey().getEncoded()).isEqualTo(certificate.getPublicKey().getEncoded());

        // create KeyStore
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);

        // Store private key with certificate
        UUID alias = X509CertUtils.store(keyStore, ecPrivateKey.getKey(), new char[]{0}, certificate);

        Assertions.assertThat(alias).isNotNull();

        // Get KeyStore entry
        KeyStore.Entry en = keyStore.getEntry(alias.toString(), new KeyStore.PasswordProtection(new char[]{0}));
        Assertions.assertThat(en).isInstanceOf(KeyStore.PrivateKeyEntry.class);

        // Does the info match
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) en;

        Assertions.assertThat(ecPrivateKey.getKey().getEncoded()).isEqualTo(privateKeyEntry.getPrivateKey().getEncoded());
        Assertions.assertThat(certificate.getEncoded()).isEqualTo(privateKeyEntry.getCertificate().getEncoded());

    }

    @Test
    public void testStore_withPassword() throws Exception {

        KeyReaderPEM keyReaderPEM = new KeyReaderPEM();

        String content = IOUtil.readFileToString("src/test/resources/sample-pem-encoded-objects/ecprivkey.pem");
        List<AtbashKey> keys = keyReaderPEM.parseContent(content);
        Assertions.assertThat(keys).hasSize(2);
        Assertions.assertThat(keys.get(0).getSecretKeyType().getKeyType()).isEqualTo(KeyType.EC);

        AtbashKey ecPrivateKey = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys).get(0);
        AtbashKey ecPublicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys).get(0);

        content = IOUtil.readFileToString("src/test/resources/sample-pem-encoded-objects/eccert.pem");
        X509Certificate certificate = X509CertUtils.parse(content);

        // Check if the loaded certificate has public key that matches with the EC key that was loaded
        Assertions.assertThat(certificate).isNotNull();
        Assertions.assertThat(ecPublicKey.getKey().getEncoded()).isEqualTo(certificate.getPublicKey().getEncoded());

        // create KeyStore
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);

        // Store private key with certificate
        String password = "secret";
        UUID alias = X509CertUtils.store(keyStore, ecPrivateKey.getKey(), password.toCharArray(), certificate);

        Assertions.assertThat(alias).isNotNull();

        // Get KeyStore entry
        KeyStore.Entry en = keyStore.getEntry(alias.toString(), new KeyStore.PasswordProtection(password.toCharArray()));
        Assertions.assertThat(en).isInstanceOf(KeyStore.PrivateKeyEntry.class);

        // Does the info match
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) en;

        Assertions.assertThat(ecPrivateKey.getKey().getEncoded()).isEqualTo(privateKeyEntry.getPrivateKey().getEncoded());
        Assertions.assertThat(certificate.getEncoded()).isEqualTo(privateKeyEntry.getCertificate().getEncoded());
    }
}
