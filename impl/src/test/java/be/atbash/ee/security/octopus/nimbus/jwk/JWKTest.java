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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.nimbus.IOUtil;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.json.Json;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;


/**
 * Tests the base JWK class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWKTest {

    @Test
    public void testMIMEType() {

        Assertions.assertThat(JWK.MIME_TYPE).isEqualTo("application/jwk+json; charset=UTF-8");
    }


    private void validateJWKFromX509Cert(JWK jwk, KeyType expectedKeyType) {

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(expectedKeyType);
        Assertions.assertThat(jwk.getAlgorithm()).isNull();
        Assertions.assertThat(jwk.getKeyUse()).isNull();
        Assertions.assertThat(jwk.getKeyOperations()).isNull();
        Assertions.assertThat(jwk.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(jwk.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(jwk.isPrivate()).isFalse();

        if (KeyType.RSA.equals(expectedKeyType)) {
            Assertions.assertThat(jwk instanceof RSAKey).isTrue();
        } else if (KeyType.EC.equals(expectedKeyType)) {
            Assertions.assertThat(jwk instanceof ECKey).isTrue();
        } else {
            Assertions.fail("Unknown KeyType");
        }
    }

    @Test
    public void testParseRSAJWKFromX509Cert() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();
        JWK jwk = JWK.parse(cert);
        validateJWKFromX509Cert(jwk, KeyType.RSA);
    }

    @Test
    public void testParseECJWKFromX509Cert() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();
        JWK jwk = JWK.parse(cert);
        validateJWKFromX509Cert(jwk, KeyType.EC);
        Assertions.assertThat(((ECKey) jwk).getCurve()).isEqualTo(Curve.P_256);
    }

    @Test
    public void testParseRSAJWKFromX509Cert_pem() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        JWK jwk = JWK.parseFromPEMEncodedX509Cert(pemEncodedCert);
        validateJWKFromX509Cert(jwk, KeyType.RSA);
    }

    @Test
    public void testParseECJWKFromX509Cert_pem() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        JWK jwk = JWK.parseFromPEMEncodedX509Cert(pemEncodedCert);
        validateJWKFromX509Cert(jwk, KeyType.EC);
        Assertions.assertThat(((ECKey) jwk).getCurve()).isEqualTo(Curve.P_256);
    }

    @Test
    public void testLoadRSAJWKFromKeyStore()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        // Generate key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        KeyPair kp = gen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        // Generate certificate
        X500Name issuer = new X500Name("cn=c2id");
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        Date now = new Date();
        Date nbf = new Date(now.getTime() - 1000L);
        Date exp = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // in 1 year
        X500Name subject = new X500Name("cn=c2id");
        JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                nbf,
                exp,
                subject,
                publicKey
        );
        KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
        x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
        X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());

        // Store
        keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new Certificate[]{cert});

        // Load
        RSAKey rsaKey = (RSAKey) JWK.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(rsaKey).isNotNull();
        Assertions.assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(rsaKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(rsaKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(rsaKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(rsaKey.isPrivate()).isTrue();

        // Try to load with bad pin
        Assertions.assertThatThrownBy(
                        () -> JWK.load(keyStore, "1", "".toCharArray()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't retrieve private RSA key (bad pin?): Cannot recover key");
    }

    @Test
    public void testLoadECJWKFromKeyStore()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        // Generate key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_521.toECParameterSpec());
        KeyPair kp = gen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

        // Generate certificate
        X500Name issuer = new X500Name("cn=c2id");
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        Date now = new Date();
        Date nbf = new Date(now.getTime() - 1000L);
        Date exp = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // in 1 year
        X500Name subject = new X500Name("cn=c2id");
        JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                nbf,
                exp,
                subject,
                publicKey
        );
        KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
        x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
        X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());

        // Store
        keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new Certificate[]{cert});

        // Load
        ECKey ecKey = (ECKey) JWK.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(ecKey).isNotNull();
        Assertions.assertThat(ecKey.getCurve()).isEqualTo(Curve.P_521);
        Assertions.assertThat(ecKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(ecKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(ecKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(ecKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(ecKey.isPrivate()).isTrue();

        // Try to load with bad pin
        Assertions.assertThatThrownBy(
                        () -> JWK.load(keyStore, "1", "".toCharArray()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't retrieve private EC key (bad pin?): Cannot recover key");
    }

    @Test
    public void testLoadSecretKeyFromKeyStore()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey secretKey = gen.generateKey();

        keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));

        OctetSequenceKey octJWK = (OctetSequenceKey) JWK.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(octJWK).isNotNull();
        Assertions.assertThat(octJWK.getKeyID()).isEqualTo("1");
        Assertions.assertThat(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray())).isTrue();
    }

    @Test
    public void testLoadJWK_notFound()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        Assertions.assertThat(JWK.load(keyStore, "no-such-key-id", "".toCharArray())).isNull();
    }

    @Test
    public void testParseOKP()
            throws Exception {

        String json = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";

        JWK jwk = JWK.parse(json);
        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.OKP);

        OctetKeyPair okp = (OctetKeyPair) jwk;

        Assertions.assertThat(okp.getCurve()).isEqualTo(Curve.X448);
        Assertions.assertThat(okp.getX().toString()).isEqualTo("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk");
        Assertions.assertThat(okp.getKeyID()).isEqualTo("Dave");
        Assertions.assertThat(okp.isPrivate()).isFalse();
    }

    @Test
    public void testParseJsonNotJWK() {
        String json = "{\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
        Assertions.assertThatThrownBy(
                        () -> JWK.parse(json))
                .isInstanceOf(ParseException.class)
                .hasMessage("Missing key type 'kty' parameter");
    }

    @Test
    public void testParseJsonNotJSON() {
        String json = "ThisIsJustSomeRandomText";
        Assertions.assertThatThrownBy(
                        () -> JWK.parse(json))
                .isInstanceOf(ParseException.class);

    }

    @Test
    public void testParseMissingKty() {

        Assertions.assertThatThrownBy(
                        () -> JWK.parse(Json.createObjectBuilder().build()))
                .isInstanceOf(ParseException.class)
                .hasMessage("Missing key type 'kty' parameter");
    }

}
