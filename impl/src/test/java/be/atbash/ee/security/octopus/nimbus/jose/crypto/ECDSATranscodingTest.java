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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.GenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSA;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.InvalidBase64ValueException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Based on code from Vladimir Dzhuvinov
 */
class ECDSATranscodingTest {

    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/399/
    @Test
    void testRejectIllegalSignatureSizesBeforeTranscodeToDER_oneByteOff()
            throws JOSEException, ParseException {

        for (JWSAlgorithm alg : JWSAlgorithm.Family.EC) {

            GenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                    .withKeyId("kid")
                    .withCurveName(Curve.forJWSAlgorithm(alg).iterator().next().getStdName())
                    .build();
            List<AtbashKey> atbashKeys = new KeyGenerator().generateKeys(parameters);

            JWSObject jwsObject = new JWSObject(new JWSHeader(alg), new Payload("Elliptic cure"));

            List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
            Assertions.assertThat(privateKeys).hasSize(1);

            jwsObject.sign(new ECDSASigner(privateKeys.get(0)));

            String string = jwsObject.serialize();

            JWSObject parsedJWSObject = JWSObject.parse(string);

            // Append extra byte to signature portion
            // (don't simply append char to base64url - not
            // guaranteed to modify the base64url encoded bytes!)
            String modifiedString =
                    parsedJWSObject.getParsedParts()[0].toString() + // header
                            "." +
                            parsedJWSObject.getParsedParts()[1].toString() + // payload
                            "." +
                            Base64URLValue.encode(ByteUtils.concat(parsedJWSObject.getParsedParts()[2].decode(), new byte[]{(byte) 'X'})) // append extra char
                    ;

            JWSObject modifiedJWSObject = JWSObject.parse(modifiedString);

            List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
            Assertions.assertThat(publicKeys).hasSize(1);

            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKeys.get(0).getKey());
            Assertions.assertThat(modifiedJWSObject.verify(verifier)).isFalse();
        }
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/399/
    @Test
    void testTranscodingFunWithBase64URL_ES256()
            throws JOSEException, ParseException {

        GenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .withCurveName(Curve.P_256.getStdName())
                .build();
        List<AtbashKey> atbashKeys = new KeyGenerator().generateKeys(parameters);

        JWSObject es256 = new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload("Elliptic cure"));

        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        Assertions.assertThat(privateKeys).hasSize(1);

        es256.sign(new ECDSASigner(privateKeys.get(0)));

        String s = es256.serialize();

        // Append extra char to final signature portion
        JWSObject es256mod = JWSObject.parse(s + "X");

        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        Assertions.assertThat(publicKeys).hasSize(1);

        ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKeys.get(0).getKey());
        Assertions.assertThat(es256mod.verify(verifier)).isFalse();

    }

    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/399/
    @Test
    void testTranscodingFunWithBase64URL_ES384()
            throws JOSEException, ParseException {

        GenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .withCurveName(Curve.P_384.getStdName())
                .build();
        List<AtbashKey> atbashKeys = new KeyGenerator().generateKeys(parameters);

        JWSObject es384 = new JWSObject(new JWSHeader(JWSAlgorithm.ES384), new Payload("Elliptic cure"));

        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        Assertions.assertThat(privateKeys).hasSize(1);

        es384.sign(new ECDSASigner(privateKeys.get(0)));

        String s = es384.serialize();

        // Append extra char to final signature portion
        JWSObject es384mod = JWSObject.parse(s + "X");


        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        Assertions.assertThat(publicKeys).hasSize(1);

        ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKeys.get(0).getKey());
        Assertions.assertThatThrownBy(
                () -> es384mod.verify(verifier)
                // Nimbus JOSE code does not fail here de to there custom implementation of Base64
        ).isInstanceOf(InvalidBase64ValueException.class);

    }

    @Test
    @Disabled // Signature not available on JDK 1.8
    public void testTranscoding_concat_to_DER() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        Signature signature = Signature.getInstance("SHA256WithECDSAInP1363Format");
        signature.initSign(keyPair.getPrivate());
        signature.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytesConcat = signature.sign();

        byte[] signatureBytesDER = ECDSA.transcodeSignatureToDER(signatureBytesConcat);
        signature = Signature.getInstance("SHA256WithECDSA");
        signature.initVerify(keyPair.getPublic());
        signature.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThat(signature.verify(signatureBytesDER)).isTrue();
    }

    @Test
    @Disabled // Signature not available on JDK 1.8
    public void testTranscoding_DER_to_concat() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        Signature signature = Signature.getInstance("SHA256WithECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytesDER = signature.sign();

        byte[] signatureBytesConcat = ECDSA.transcodeSignatureToConcat(signatureBytesDER, 64);
        signature = Signature.getInstance("SHA256WithECDSAInP1363Format");
        signature.initVerify(keyPair.getPublic());
        signature.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
        Assertions.assertThat(signature.verify(signatureBytesConcat)).isTrue();
    }


    // iss 473
    @Test
    public void testTranscoding_toDER_blank() {

        Assertions.assertThatThrownBy(
                        () -> ECDSA.transcodeSignatureToDER(new byte[64])
                ).isInstanceOf(JOSEException.class)
                .hasMessage("Index 64 out of bounds for length 64");

    }

    @Test
    public void testTranscoding_toDER_rBlank_sOnes() throws JOSEException {

        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        Arrays.fill(sBytes, Byte.MAX_VALUE);

        Assertions.assertThatNoException().isThrownBy(
                () -> ECDSA.transcodeSignatureToDER(ByteUtils.concat(rBytes, sBytes))
        );

    }

    // iss 473
    @Test
    public void testTranscoding_toDER_rOnes_sZeros() {

        byte[] rBytes = new byte[32];
        Arrays.fill(rBytes, Byte.MAX_VALUE);
        byte[] sBytes = new byte[32];

        Assertions.assertThatThrownBy(
                        () -> ECDSA.transcodeSignatureToDER(ByteUtils.concat(rBytes, sBytes)))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Index 64 out of bounds for length 64");

    }

    @Test
    public void testTranscoding_DER_to_concat_blank() throws JOSEException {

        byte[] derZeroZero = Base64.getDecoder().decode("MAYCAQACAQA=");

        byte[] concat = ECDSA.transcodeSignatureToConcat(derZeroZero, 64);

        Assertions.assertThat(concat).hasSize(64);
        Assertions.assertThat(ByteUtils.isZeroFilled(concat)).isTrue();

        Assertions.assertThatThrownBy(
                        () -> ECDSA.transcodeSignatureToDER(concat))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Index 64 out of bounds for length 64");

    }
}
