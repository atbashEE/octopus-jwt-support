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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.AESEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSAEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.BadJOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.*;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.TestReflectionUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

class DefaultJWTProcessorTest {

    private final TestLogger logger = TestLoggerFactory.getTestLogger(DefaultJWTClaimsVerifier.class);

    @AfterEach
    public void tearDown() {
        MDC.clear();
        logger.clear();
    }

    @Test
    void testConstructor() throws NoSuchFieldException {

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        Assertions.assertThat((KeySelector) TestReflectionUtils.getValueOf(processor, "jwsKeySelector")).isNull();
        Assertions.assertThat((KeySelector) TestReflectionUtils.getValueOf(processor, "jweKeySelector")).isNull();

        Assertions.assertThat((JWSVerifierFactory) TestReflectionUtils.getValueOf(processor, "jwsVerifierFactory")).isInstanceOf(DefaultJWSVerifierFactory.class);
        Assertions.assertThat((JWEDecrypterFactory) TestReflectionUtils.getValueOf(processor, "jweDecrypterFactory")).isInstanceOf(DefaultJWEDecrypterFactory.class);

        Assertions.assertThat((JWTVerifier) TestReflectionUtils.getValueOf(processor, "claimsVerifier")).isInstanceOf(DefaultJWTClaimsVerifier.class);


    }

    @Test
    void testVerifyClaimsAllow() {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://openid.c2id.com")
                .subject("alice")
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        processor.setJWTClaimsSetVerifier((header, claimsSet) -> claimsSet.getIssuer() != null && claimsSet.getIssuer().equals("https://openid.c2id.com"));

        JWTClaimsSet claimSet = processor.process(jwt);
        Assertions.assertThat(claimSet.getSubject()).isEqualTo("alice");
        Assertions.assertThat(claimSet.getIssuer()).isEqualTo("https://openid.c2id.com");
    }


    @Test
    void testVerifyClaimsDeny() {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://test.c2id.com")
                .subject("alice")
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        processor.setJWTClaimsSetVerifier((header, claimsSet) -> {

            if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com")) {
                logger.error("Unexpected/missing issuer");
                return false;
            }
            return true;
        });

        Assertions.assertThatThrownBy(() -> processor.process(jwt))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("JWT Claims validation failed");
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        Assertions.assertThat(loggingEvents.get(0).getMessage()).isEqualTo("Unexpected/missing issuer");

    }


    @Test
    void testProcessInvalidHmac() {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        SecureRandom random = new SecureRandom();

        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        final SecretKey invalidKey = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(invalidKey));

        Assertions.assertThatThrownBy(() -> processor.process(jwt))
                .isInstanceOf(InvalidJWTException.class)
                .hasMessage("Signed JWT rejected: Invalid signature");
    }

    @Test
    void testProcessHmac() {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        SecureRandom random = new SecureRandom();

        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        JWTClaimsSet claimsSet = processor.process(jwt);
        Assertions.assertThat(claimsSet.getClaims()).hasSize(1);
        Assertions.assertThat(claimsSet.getSubject()).isEqualTo("alice");
    }

    @Test
    void testProcessAES() {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        SecureRandom random = new SecureRandom();

        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        JWTClaimsSet claimsSet = processor.process(jwt);
        Assertions.assertThat(claimsSet.getClaims()).hasSize(1);
        Assertions.assertThat(claimsSet.getSubject()).isEqualTo("alice");
    }

    @Test
    void testProcessNestedJWT() throws Exception {

        // See http://tools.ietf.org/html/rfc7519#appendix-A.2

        String jwt = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJraWQiOiJlbmNLZXkiLCJlbmMiOiJBMjU2R0NNIn0" +
                "." +
                "sCtCeowKnWY6ZU9uLvOZh6yw_lOGKpE5xyHrcJt0U5QsgxCYl3aPerOB_wHanl8lYLh0g-byZ0xx1qrqI0-vFvVsFDyD" +
                "yXEedXXDwLPQF-U5RNPm8r_HBg-ikq7AkovhZue24Cl6omJ8hZXyz2G_BuYo_w_Oj1f8GmLT0sucFgZX8Y4tdJZ3STNd" +
                "pKtqeSgHJvmcdIQKu3EEWx38ivkaE4DE90Bzul_hn8Qb4-FDEq8Px_86UiwghHCgeAAgWDk9KWLYSguSdL3MFBdcqlwa" +
                "No5ApQzVPtfmk_pnI8fGRnhx9zLDV5nyZ8H7m-K_ERmD7EX3Uf-mKTfCXmTaXtEISQ" +
                "." +
                "GpJ6PUx02A0qVYTK" +
                "." +
                "4GLZJZ9OLkQizidz3jQpkUxoRUqgRLZ5SUKrYizTMZKUn8YrYkWiyJb30Ap-qpUyChH74PjkRkHTKzISNLa5k-UPMGCBL3Yt_4yu" +
                "HgmOmoA6vPpOALZ-oWo95rtVy9jv6qPlSiQy_MVDaRQWFROkrn_5w-VgwWYKuHQ4Zj9zahkgW6eRiyMqFlp8B0tnO7IR" +
                "vafk93muniDcqEkhKNCgCKR0Nwsk2Xrh0ARPBc9CuqzU55PltYOtaZQCdzhEIdzs69DvISRBP9XxqzmzRaSUoIkn-UNf" +
                "jFPHHToyrqV6E12zhZAbVyI9eibYV9v2rV5ADcA7swYWjIKfyhq8yCTiI2XaP6RJcfL_al4JY5a4et05sC7fTwMULorc" +
                "5ANE5Q6kZU6fQvZ9lejYn9QVkBgCggzQBm5wikvxa1V_4QMX3XUf7p1Qg-abIn4Z-UOSmS-aoZfrnSrcNqYwuCu50HMS" +
                "9O5gdi0XX7KXxuf8rgoFszut7qLoD9_P0982y4JoMWL1VIqDOGtwekoWHF1Fv_lAc56seMgVwskeLSMLjSBfnKclQwiY" +
                "eMf0v2ELQOPL_NfdoRsu25s0V0DIzo3HVQ5PO5cGxAMSrwacY50j2qv5tUScogh3r3ezPqz9y-vGkj1GyENyV13CtLY" +
                "." +
                "xHMtsysUarhiXQ5ylDxpwg";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();
        processor.setJWTClaimsSetVerifier(null); // Remove claims verifier, JWT past expiration timestamp

        String jwkForJWT = "{\"kty\":\"RSA\"," +
                "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
                "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
                "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
                "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
                "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
                "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
                "\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
                "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
                "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
                "\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
                "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
                "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
                "\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
                "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
                "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
                "\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
                "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
                "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
                "\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
                "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
                "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
                "}";

        processor.setJWSKeySelector(new TestJWKKeySelector(jwkForJWT, true));

        String jwkForJWE = "{\"kty\":\"RSA\"," +
                "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
                "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
                "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
                "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
                "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
                "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
                "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
                "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
                "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
                "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
                "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
                "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
                "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
                "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
                "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
                "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
                "}";

        processor.setJWEKeySelector(new TestJWKKeySelector(jwkForJWE, false));

        JWTClaimsSet claims = processor.process(JWTParser.parse(jwt));

        Assertions.assertThat(claims.getIssuer()).isEqualTo("joe");
        Assertions.assertThat(claims.getExpirationTime()).isNotNull();
        Assertions.assertThat(claims.getExpirationTime().getTime()).isEqualTo(1300819380L * 1000L);
        Assertions.assertThat(claims.getBooleanClaim("http://example.com/is_root")).isTrue();
        Assertions.assertThat(claims.getClaims()).hasSize(3);
    }

    @Test
    void testRejectPlain() throws Exception {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

        PlainJWT jwt = new PlainJWT(claims);

        try {
            new DefaultJWTProcessor().process(jwt);
        } catch (BadJOSEException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
        }

        try {
            new DefaultJWTProcessor().process(jwt);
        } catch (BadJOSEException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
        }
    }

    @Test
    void testNoJWSKeyCandidates() {

        // See http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        // FIXME Another test where no keyId in header but a single private Key in KeySelector. Then that one should be picked up.
        processor.setJWSKeySelector(new TestKeySelector(null));

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jws)))
                .isInstanceOf(InvalidJWTException.class)
                .hasMessage("No key found for keyId 'null'");
    }

    @Test
    void testNoJWEKeyCandidates() {

        String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" +
                "In0." +
                "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" +
                "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" +
                "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" +
                "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" +
                "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" +
                "JGTO_z3Wfo5zsqwkxruxwA." +
                "UmVkbW9uZCBXQSA5ODA1Mg." +
                "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" +
                "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" +
                "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" +
                "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" +
                "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" +
                "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" +
                "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" +
                "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" +
                "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" +
                "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." +
                "AVO9iT5AV4CzvDJCdhSFlQ";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWEKeySelector(new TestKeySelector(null));  // FIXME Test where a single key is in the selector which then gets used for keyId null.

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jwt)))
                .isInstanceOf(InvalidJWTException.class)
                .hasMessage("No key found for keyId 'null'");
    }

    @Test
    void testNoJWSKeySelector() {

        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jws)))
                .isInstanceOf(BadJOSEException.class)
                .hasMessage("Signed JWT rejected: No JWS key selector is configured");
    }

    @Test
    void testNoJWSFactory() {

        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        Key key = new SecretKeySpec(new Base64URLValue("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow").decode(), "HMAC");

        processor.setJWSKeySelector(new TestKeySelector(key));
        processor.setJWSVerifierFactory(null);

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jws)))
                .isInstanceOf(JOSEException.class)
                .hasMessage("No JWS verifier is configured");

    }

    @Test
    void testNoJWEKeySelector() {

        String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" +
                "In0." +
                "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" +
                "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" +
                "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" +
                "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" +
                "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" +
                "JGTO_z3Wfo5zsqwkxruxwA." +
                "UmVkbW9uZCBXQSA5ODA1Mg." +
                "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" +
                "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" +
                "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" +
                "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" +
                "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" +
                "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" +
                "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" +
                "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" +
                "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" +
                "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." +
                "AVO9iT5AV4CzvDJCdhSFlQ";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jwe)))
                .isInstanceOf(BadJOSEException.class)
                .hasMessage("Encrypted JWT rejected: No JWE key selector is configured");
    }

    @Test
    void testNoJWEFactory() {

        String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" +
                "In0." +
                "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" +
                "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" +
                "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" +
                "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" +
                "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" +
                "JGTO_z3Wfo5zsqwkxruxwA." +
                "UmVkbW9uZCBXQSA5ODA1Mg." +
                "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" +
                "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" +
                "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" +
                "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" +
                "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" +
                "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" +
                "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" +
                "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" +
                "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" +
                "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." +
                "AVO9iT5AV4CzvDJCdhSFlQ";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        String jwk = "{\"kty\":\"RSA\"," +
                "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
                "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
                "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
                "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
                "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
                "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
                "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
                "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
                "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
                "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
                "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
                "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
                "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
                "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
                "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
                "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
                "}";


        processor.setJWEKeySelector(new TestJWKKeySelector(jwk, false));

        processor.setJweDecrypterFactory(null);

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jwe)))
                .isInstanceOf(JOSEException.class)
                .hasMessage("No JWE decrypter is configured");
    }

    @Test
    void testJWTExpired() {

        Date now = new Date();
        Date yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://openid.c2id.com")
                .subject("alice")
                .expirationTime(yesterday)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        Assertions.assertThatThrownBy(() -> processor.process(JWTParser.parse(jwt.serialize())))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("JWT Claims validation failed");
        String message = MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON);
        Assertions.assertThat(message).startsWith("The token was expired (exp = ");
    }

    @Test
    void testJWTBeforeUse() {

        Date now = new Date();
        Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://openid.c2id.com")
                .subject("alice")
                .notBeforeTime(tomorrow)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

        jwt.sign(new MACSigner(key));

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(key));

        Assertions.assertThatThrownBy(() -> processor.process(jwt))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("JWT Claims validation failed");

        String message = MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON);
        Assertions.assertThat(message).startsWith("The token should not be used (nbf = ");

    }

    @Test
    void testNestedWithMissingContentTypeHeader() {

        byte[] random32 = new byte[32];
        new SecureRandom().nextBytes(random32);
        SecretKey hmacKey = new SecretKeySpec(random32, "HmacSha256");

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(new MACSigner(hmacKey));

        SecretKey aesKey = new SecretKeySpec(random32, "AES");
        JWEObject jweObject = new JWEObject(
                new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM),
                new Payload(signedJWT));
        jweObject.encrypt(new AESEncrypter(aesKey));

        String jwe = jweObject.serialize();

        DefaultJWTProcessor proc = new DefaultJWTProcessor();
        proc.setJWEKeySelector(new TestKeySelector(aesKey));

        proc.setJWSKeySelector(new TestKeySelector(hmacKey));

        Assertions.assertThatThrownBy(() -> proc.process(JWTParser.parse(jwe)))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Payload of JWE object is not a valid JSON object");
    }


    @Test
    void testNestedWithPlainJWT() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
        PlainJWT plainJWT = new PlainJWT(claimsSet);

        byte[] random32 = new byte[32];
        new SecureRandom().nextBytes(random32);
        SecretKey aesKey = new SecretKeySpec(random32, "AES");
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM).contentType("JWT").build(),
                new Payload(plainJWT.serialize()));
        jweObject.encrypt(new AESEncrypter(aesKey));

        String jwe = jweObject.serialize();

        DefaultJWTProcessor proc = new DefaultJWTProcessor();
        proc.setJWEKeySelector(new TestKeySelector(aesKey));

        Assertions.assertThatThrownBy(() -> proc.process(JWTParser.parse(jwe)))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("The payload is not a nested signed JWT");
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
    @Test
    void testRejectPlainNestedJWT_noCTY()
            throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID("1")
                .build();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
        SecretKey hmacKey = keyGenerator.generateKey();
        OctetSequenceKey hmacJWK = new OctetSequenceKey.Builder(hmacKey).build();

        DefaultJWTProcessor proc = new DefaultJWTProcessor();
        proc.setJWEKeySelector(new TestKeySelector(rsaJWK.toRSAPrivateKey()));

        proc.setJWSKeySelector(new TestKeySelector(hmacJWK.toSecretKey()));


        PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build());

        JWEObject jweObject = new JWEObject(
                new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
                new Payload(plainJWT.serialize()));
        jweObject.encrypt(new RSAEncrypter(rsaJWK));

        String jwe = jweObject.serialize();

        Assertions.assertThatThrownBy(() -> proc.process(JWTParser.parse(jwe)))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Payload of JWE object is not a valid JSON object");
    }

    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
    @Test
    void testRejectPlainNestedJWT_withCTY()
            throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID("1")
                .build();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
        SecretKey hmacKey = keyGenerator.generateKey();
        OctetSequenceKey hmacJWK = new OctetSequenceKey.Builder(hmacKey).build();

        DefaultJWTProcessor proc = new DefaultJWTProcessor();
        proc.setJWEKeySelector(new TestKeySelector(rsaJWK.toRSAPrivateKey()));

        proc.setJWSKeySelector(new TestKeySelector(hmacJWK.toSecretKey()));


        PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build());

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .contentType("JWT")
                        .build(),
                new Payload(plainJWT.serialize()));
        jweObject.encrypt(new RSAEncrypter(rsaJWK));

        String jwe = jweObject.serialize();

        Assertions.assertThatThrownBy(() -> proc.process(JWTParser.parse(jwe)))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("The payload is not a nested signed JWT");
    }


    // issue https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/250/error-on-jwe-decryption-wrong-algorithm
    @Test
    void testJCAKeyAlgAccepted()
            throws Exception {

        String hostId = "subject";

        String sharedSecret = "SharedSecret";
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(sharedSecret.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        // create the JWT

        JWSSigner signer = new MACSigner(secretKey.getEncoded());

        JWTClaimsSet inputClaimsSet = new JWTClaimsSet.Builder()
                .subject(hostId)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                .build();

        SignedJWT hmacJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), inputClaimsSet);

        hmacJWT.sign(signer);

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build(),
                new Payload(hmacJWT)
        );

        jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));

        String jweString = jweObject.serialize();

        // parse the JWT

        JWT jwt = JWTParser.parse(jweString);

        if (!(jwt instanceof EncryptedJWT)) {
            throw new RuntimeException("encrypted JWT required");
        }

        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();

        jwtProcessor.setJWEKeySelector(new TestKeySelector(secretKey));

        jwtProcessor.setJWSKeySelector(new TestKeySelector(secretKey));

        JWTClaimsSet outputClaimsSet = jwtProcessor.process(jwt);

        Assertions.assertThat(outputClaimsSet.getSubject()).isEqualTo(hostId);
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/257/error-on-jwe-decryption-with-aeskw
    @Test
    void testJCAKeyAlgAccepted_AES_KW() throws Exception {

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        OctetSequenceKey aesKey = new OctetSequenceKey.Builder(gen.generateKey().getEncoded()).build();

        // create the JWT

        JWTClaimsSet inputClaimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                .build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(
                new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM).build(),
                inputClaimsSet
        );

        encryptedJWT.encrypt(new AESEncrypter(aesKey));

        String jweString = encryptedJWT.serialize();

        JWT jwt = JWTParser.parse(jweString);

        if (!(jwt instanceof EncryptedJWT)) {
            throw new RuntimeException("encrypted JWT required");
        }

        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();

        jwtProcessor.setJWEKeySelector(new TestKeySelector(aesKey.toSecretKey()));

        JWTClaimsSet outputClaimsSet = jwtProcessor.process((EncryptedJWT) jwt);

        Assertions.assertThat(outputClaimsSet.getSubject()).isEqualTo("alice");
    }


    @Test
    void testPlainJWT_noJWSTypeVerifier() {

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        Assertions.assertThatThrownBy(() -> processor.process(new PlainJWT(new JWTClaimsSet.Builder().build())))
                .isInstanceOf(BadJOSEException.class)
                .hasMessage("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
    }

    @Test
    public void process_wrongTyp() {
        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://openid.c2id.com")
                .subject("alice")
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JOSE)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        Assertions.assertThatThrownBy(() -> processor.process(jwt))
                .isInstanceOf(BadJOSEException.class)
                .hasMessage("JOSE header \"typ\" (type) \"JOSE\" not allowed");
        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON))
                .isEqualTo("The provided token did not specify the correct 'JWT' typ in the header (header = {\"alg\":\"HS256\",\"typ\":\"JOSE\"})");
    }

    private static class TestKeySelector extends KeySelector {
        private final Key key;

        TestKeySelector(Key key) {
            this.key = key;
        }

        @Override
        public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
            return (T) key;
        }
    }

    private static class TestJWKKeySelector extends KeySelector {
        private Key key;

        TestJWKKeySelector(String jwk, boolean publicKey) {

            try {
                RSAKey jwkKey = RSAKey.parse(jwk);
                if (publicKey) {
                    key = jwkKey.toRSAPublicKey();
                } else {
                    key = jwkKey.toRSAPrivateKey();

                }
            } catch (ParseException e) {
                Assertions.fail(e.getMessage());
            }
        }

        @Override
        public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
            return (T) key;
        }
    }
}