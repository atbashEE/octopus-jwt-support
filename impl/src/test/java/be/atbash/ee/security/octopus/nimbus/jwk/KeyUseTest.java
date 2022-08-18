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
import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;


/**
 * Tests the key use enumeration.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class KeyUseTest {

    @Test
    public void testConstantIdentifiers() {

        Assertions.assertThat(KeyUse.SIGNATURE.identifier()).isEqualTo("sig");
        Assertions.assertThat(KeyUse.SIGNATURE.getValue()).isEqualTo("sig");
        Assertions.assertThat(KeyUse.SIGNATURE.toString()).isEqualTo("sig");

        Assertions.assertThat(KeyUse.ENCRYPTION.identifier()).isEqualTo(HeaderParameterNames.ENCRYPTION_ALGORITHM);
        Assertions.assertThat(KeyUse.ENCRYPTION.getValue()).isEqualTo(HeaderParameterNames.ENCRYPTION_ALGORITHM);
        Assertions.assertThat(KeyUse.ENCRYPTION.toString()).isEqualTo(HeaderParameterNames.ENCRYPTION_ALGORITHM);
    }

    @Test
    public void testCustomIdentifier()
            throws ParseException {

        KeyUse tls = new KeyUse("tls");
        Assertions.assertThat(tls.identifier()).isEqualTo("tls");
        Assertions.assertThat(tls.getValue()).isEqualTo("tls");
        Assertions.assertThat(tls.toString()).isEqualTo("tls");

        Assertions.assertThat(KeyUse.parse("tls").identifier()).isEqualTo("tls");
        Assertions.assertThat(tls.equals(new KeyUse("tls"))).isTrue();
    }

    @Test
    public void testParseConstants()
            throws ParseException {

        Assertions.assertThat(KeyUse.parse("sig")).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(KeyUse.parse(HeaderParameterNames.ENCRYPTION_ALGORITHM)).isEqualTo(KeyUse.ENCRYPTION);
    }

    @Test
    public void testParseException_empty() {

        Assertions.assertThatThrownBy(
                        () -> KeyUse.parse(""))
                .isInstanceOf(ParseException.class)
                .hasMessage("JWK use value must not be empty or blank");
    }

    @Test
    public void testParseException_blank() {

        Assertions.assertThatThrownBy(
                        () -> KeyUse.parse("  "))
                .isInstanceOf(ParseException.class)
                .hasMessage("JWK use value must not be empty or blank");
    }

    @Test
    public void testParseNull()
            throws ParseException {

        Assertions.assertThat(KeyUse.parse(null)).isNull();
    }

    @Test
    public void testInferKeyUseFromX509Cert_RSAENC() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(x509Cert).isNotNull();
        Assertions.assertThat(KeyUse.from(x509Cert)).isNull();
    }

    @Test
    public void testInferKeyUseFromX509Cert_ECDH() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(x509Cert).isNotNull();
        Assertions.assertThat(KeyUse.from(x509Cert)).isNull();
    }

    @Test
    public void testKeyUseNotSpecified()
            throws Exception {

        // Generate self-signed certificate
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

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
                keyPair.getPublic()
        );

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(keyPair.getPrivate()));
        X509Certificate x509Cert = X509CertUtils.parse(certHolder.getEncoded());
        Assertions.assertThat(x509Cert).isNotNull();
        Assertions.assertThat(KeyUse.from(x509Cert)).isNull();
    }
}
