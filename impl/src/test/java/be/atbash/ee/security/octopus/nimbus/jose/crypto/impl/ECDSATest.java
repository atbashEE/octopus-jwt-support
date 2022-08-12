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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECParameterTable;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.BigIntegerUtils;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

class ECDSATest {

    // https://tools.ietf.org/html/rfc7515#appendix-A.3
    @Test
    void testES256_encodingRoundTrip() throws JOSEException {

        Base64URLValue b64sig = new Base64URLValue("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");

        byte[] jwsSignature = b64sig.decode();

        byte[] derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);

        Assertions.assertThat(jwsSignature).isEqualTo(ECDSA.transcodeSignatureToConcat(derSignature, 64));
    }


    // https://tools.ietf.org/html/rfc7520#section-4.3
    @Test
    public void testES512_encodingRoundTrip() throws JOSEException {

        Base64URLValue b64sig = new Base64URLValue(
                "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb" +
                        "u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv" +
                        "AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2");

        byte[] jwsSignature = b64sig.decode();

        byte[] derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);

        Assertions.assertThat(jwsSignature).isEqualTo(ECDSA.transcodeSignatureToConcat(derSignature, 132));
    }

    @Test
    @Disabled // Signature not available on JDK 1.8
    public void test_default_JCE_for_CVE_2022_21449__zeroSignature() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();

        byte[] blankSignature = new byte[64];

        Signature signature = Signature.getInstance("SHA256WithECDSAInP1363Format");

        signature.initVerify(keyPair.getPublic());
        signature.update("Hello, World".getBytes());
        boolean verify = signature.verify(blankSignature);
        Assertions.assertThat(verify).as("Your Java runtime is vulnerable to CVE-2022-21449 - Upgrade to a patched Java version!!!").isFalse();
    }

    @Test
    public void testES256_for_CVE_2022_21449__zeroSignature() throws ParseException, JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
            JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlg), new Payload("Hello, world"));

            String jwsString = new String(jwsObject.getSigningInput(), StandardCharsets.UTF_8) +
                    "." +
                    Base64URLValue.encode(new byte[ECDSA.getSignatureByteArrayLength(jwsAlg)]);

            Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();

            List<AtbashKey> keys = TestKeys.generateECKeys("kid", curve.getName());
            List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
            Assertions.assertThat(publicKeys).hasSize(1);

            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKeys.get(0).getKey());
            boolean verify = JWSObject.parse(jwsString).verify(verifier);
            Assertions.assertThat(verify).isFalse();

        }
    }

    @Test
    public void test_CVE_2022_21449__r_and_s_equal_N() throws ParseException, JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

            JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlg), new Payload("Hello, world"));

            Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();

            BigInteger n = ECParameterTable.get(curve).getOrder();
            byte[] nBytes = BigIntegerUtils.toBytesUnsigned(n);
            Assertions.assertThat(ECDSA.getSignatureByteArrayLength(jwsAlg) / 2).isEqualTo(nBytes.length);

            Base64URLValue signatureB64 = Base64URLValue.encode(ByteUtils.concat(nBytes, nBytes));

            if (JWSAlgorithm.ES256.equals(jwsAlg)) {
                // Validated test vector provided by user
                Assertions.assertThat(signatureB64.toString())
                        .isEqualTo("_____wAAAAD__________7zm-q2nF56E87nKwvxjJVH_____AAAAAP__________vOb6racXnoTzucrC_GMlUQ", signatureB64.toString());

            }

            String jwsString = new String(jwsObject.getSigningInput(), StandardCharsets.UTF_8) +
                    "." +
                    signatureB64;

            List<AtbashKey> keys = TestKeys.generateECKeys("kid", curve.getName());
            List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
            Assertions.assertThat(publicKeys).hasSize(1);

            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKeys.get(0).getKey());
            Assertions.assertThat(JWSObject.parse(jwsString).verify(verifier)).isFalse();
        }
    }

    @Test
    public void testIsLegalSignature_zeroFilled() throws JOSEException {

        int nMaxArraySize = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES512);

        for (int sigSize = 1; sigSize <= nMaxArraySize; sigSize++) {

            byte[] sigArray = new byte[sigSize];

            for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

                Assertions.assertThatThrownBy(
                                () -> ECDSA.ensureLegalSignature(sigArray, jwsAlg)
                        ).isInstanceOf(JOSEException.class)
                        .hasMessage("Blank signature");
            }
        }
    }

    @Test
    public void testIsLegalSignature_unsupportedJWSAlg() {

        List<JWSAlgorithm> jwsAlgorithmList = new LinkedList<>(JWSAlgorithm.Family.RSA);
        jwsAlgorithmList.add(JWSAlgorithm.EdDSA);

        for (JWSAlgorithm jwsAlg : jwsAlgorithmList) {

            byte[] sigArray = new byte[32]; // some 1s filled array
            Arrays.fill(sigArray, (byte) 1);

            Assertions.assertThatThrownBy(
                            () -> ECDSA.ensureLegalSignature(sigArray, jwsAlg)
                    ).isInstanceOf(JOSEException.class)
                    .hasMessage("Unsupported JWS algorithm: " + jwsAlg);
        }

    }

    @Test
    public void testIsLegalSignature_illegalSignatureLength() throws JOSEException {

        List<AtbashKey> keys = TestKeys.generateECKeys("kid", Curve.P_384.getName());
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        Assertions.assertThat(privateKeys).hasSize(1);

        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES384), new Payload("Hello, world!"));
        jwsObject.sign(new ECDSASigner((ECPrivateKey) privateKeys.get(0).getKey()));

        Assertions.assertThatThrownBy(
                        () -> ECDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ES256)
                ).isInstanceOf(JOSEException.class)
                .hasMessage("Illegal signature length");

        Assertions.assertThatThrownBy(
                        () -> ECDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ES512)
                ).isInstanceOf(JOSEException.class)
                .hasMessage("Illegal signature length");

    }

    @Test
    public void testIsLegalSignature_rZero() throws JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

            int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);

            byte[] rBytes = new byte[sigLength / 2];
            Arrays.fill(rBytes, (byte) 1);
            byte[] sBytes = new byte[sigLength / 2];

            byte[] sig = ByteUtils.concat(rBytes, sBytes);
            Assertions.assertThatThrownBy(
                            () -> ECDSA.ensureLegalSignature(sig, jwsAlg))
                    .isInstanceOf(JOSEException.class)
                    .hasMessage("S and R must not be 0");

        }
    }

    @Test
    public void testIsLegalSignature_sZero() throws JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

            int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);

            byte[] rBytes = new byte[sigLength / 2];
            byte[] sBytes = new byte[sigLength / 2];
            Arrays.fill(sBytes, (byte) 1);

            byte[] sig = ByteUtils.concat(rBytes, sBytes);

            Assertions.assertThatThrownBy(
                            () -> ECDSA.ensureLegalSignature(sig, jwsAlg))
                    .isInstanceOf(JOSEException.class)
                    .hasMessage("S and R must not be 0");
        }
    }

    @Test
    public void testIsLegalSignature_rEqualsN() throws JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

            Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
            BigInteger n = ECParameterTable.get(curve).getOrder();

            int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);

            byte[] rBytes = BigIntegerUtils.toBytesUnsigned(n);
            byte[] sBytes = new byte[sigLength / 2];
            Arrays.fill(sBytes, (byte) 1);

            byte[] sig = ByteUtils.concat(rBytes, sBytes);
            Assertions.assertThat(sig.length).isEqualTo(sigLength);

            Assertions.assertThatThrownBy(
                            () -> ECDSA.ensureLegalSignature(sig, jwsAlg))
                    .isInstanceOf(JOSEException.class)
                    .hasMessage("S and R must not exceed N");
        }
    }

    @Test
    public void testIsLegalSignature_sEqualsN() throws JOSEException {

        for (JWSAlgorithm jwsAlg : Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {

            Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
            BigInteger n = ECParameterTable.get(curve).getOrder();

            int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);

            byte[] rBytes = new byte[sigLength / 2];
            Arrays.fill(rBytes, (byte) 1);
            byte[] sBytes = BigIntegerUtils.toBytesUnsigned(n);

            byte[] sig = ByteUtils.concat(rBytes, sBytes);
            Assertions.assertThat(sig.length).isEqualTo(sigLength);

            Assertions.assertThatThrownBy(
                            () -> ECDSA.ensureLegalSignature(sig, jwsAlg))
                    .isInstanceOf(JOSEException.class)
                    .hasMessage("S and R must not exceed N");
        }
    }
}

