/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

/**
 *
 */

public class KeyStoreEncoder extends AbstractEncoder implements KeyEncoder {

    private JwtSupportConfiguration configuration;

    public KeyStoreEncoder() {
        configuration = JwtSupportConfiguration.getInstance();
    }

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {

        KeyStore keyStore = parameters.getKeyStore();
        try {

            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {

                PrivateKey key = (PrivateKey) atbashKey.getKey();
                X509Certificate certificate = generateCertificate(getPublicKey(key), key, atbashKey.getSecretKeyType().getKeyType());
                KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(key, new X509Certificate[]{certificate});
                keyStore.setEntry(atbashKey.getKeyId(), entry, new KeyStore.PasswordProtection(parameters.getKeyPassword()));
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                PublicKey key = (PublicKey) atbashKey.getKey();
                X509Certificate certificate = generateCertificate(key, null, atbashKey.getSecretKeyType().getKeyType());
                KeyStore.Entry entry = new KeyStore.TrustedCertificateEntry(certificate);
                keyStore.setEntry(atbashKey.getKeyId(), entry, null);

            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.SYMMETRIC) {
                SecretKey key = (SecretKey) atbashKey.getKey();

                keyStore.setKeyEntry(atbashKey.getKeyId(), key, parameters.getKeyPassword(), null);
            }
        } catch (KeyStoreException e) {
            throw new AtbashUnexpectedException(e);
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            keyStore.store(stream, parameters.getFilePassword());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new AtbashUnexpectedException(e);
        }
        return stream.toByteArray();
    }

    private X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, KeyType keyType) {

        try {

            Calendar start = Calendar.getInstance();
            Calendar expiry = Calendar.getInstance();
            expiry.add(Calendar.YEAR, 1);
            X500Name name = new X500Name(configuration.getNameCertificateKeyStore());
            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(name, BigInteger.ONE,
                    start.getTime(), expiry.getTime(), name, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            if (privateKey == null) {

                privateKey = createSigningKey(keyType); // this is the private key to sign the certificate. Has nothing to do with the Certificate and the public key.
            }

            ContentSigner signer = new JcaContentSignerBuilder(getCertificateSignatureAlgorithm(keyType)).setProvider(new BouncyCastleProvider()).build(privateKey);
            X509CertificateHolder holder = certificateBuilder.build(signer);
            return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);

        } catch (GeneralSecurityException | OperatorCreationException ex) {
            throw new AtbashUnexpectedException(ex);
        }
    }

    private String getCertificateSignatureAlgorithm(KeyType keyType) {
        String result;
        switch (keyType.getValue()) {
            case "RSA":
                result = configuration.getCertificateSignatureAlgorithmRSA();
                break;
            case "EC":
                result = configuration.getCertificateSignatureAlgorithmEC();
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + keyType.getValue());
        }
        return result;
    }

    private PrivateKey createSigningKey(KeyType keyType) {
        PrivateKey result;
        switch (keyType.getValue()) {
            case "RSA":
                result = createSigningKeyRSA();
                break;
            case "EC":
                result = createSigningKeyEC();
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + keyType.getValue());
        }
        return result;

    }

    private PrivateKey createSigningKeyRSA() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("cert-signing")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> atbashKeys = generator.generateKeys(generationParameters);
        AsymmetricPartKeyFilter keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE);

        List<AtbashKey> privateKeys = keyFilter.filter(atbashKeys);
        // TODO should we be on the safe side and check we have just 1 private key.
        return (PrivateKey) privateKeys.get(0).getKey();

    }

    private PrivateKey createSigningKeyEC() {
        ECGenerationParameters generationParameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("cert-signing")
                .withCurveName("P-256")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> atbashKeys = generator.generateKeys(generationParameters);
        AsymmetricPartKeyFilter keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE);

        List<AtbashKey> privateKeys = keyFilter.filter(atbashKeys);
        // TODO should we be on the safe side and check we have just 1 private key.
        return (PrivateKey) privateKeys.get(0).getKey();

    }
}
