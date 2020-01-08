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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;

import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
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
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultJWTProcessorTest {

    private TestLogger logger = TestLoggerFactory.getTestLogger(DefaultJWTClaimsVerifier.class);

    @AfterEach
    public void tearDown() {
        logger.clear();
    }


    @Test
    public void testConstructor() throws NoSuchFieldException {

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        assertThat((KeySelector) TestReflectionUtils.getValueOf(processor, "jwsKeySelector")).isNull();
        assertThat((KeySelector) TestReflectionUtils.getValueOf(processor, "jweKeySelector")).isNull();

        assertThat((JWSVerifierFactory) TestReflectionUtils.getValueOf(processor, "jwsVerifierFactory")).isInstanceOf(DefaultJWSVerifierFactory.class);
        assertThat((JWEDecrypterFactory) TestReflectionUtils.getValueOf(processor, "jweDecrypterFactory")).isInstanceOf(DefaultJWEDecrypterFactory.class);

        assertThat((JWTVerifier) TestReflectionUtils.getValueOf(processor, "claimsVerifier")).isInstanceOf(DefaultJWTClaimsVerifier.class);


    }

    @Test
    public void testVerifyClaimsAllow()
            throws Exception {

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

        processor.setJWTClaimsSetVerifier((header, claimsSet) -> {

            if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com")) {
                return false;
            }
            return true;
        });


        JWTClaimsSet claimSet = processor.process(jwt.serialize());
        assertThat(claimSet.getSubject()).isEqualTo("alice");
        assertThat(claimSet.getIssuer()).isEqualTo("https://openid.c2id.com");
    }


    @Test
    public void testVerifyClaimsDeny() throws Exception {

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

        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> processor.process(jwt.serialize()));
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("Unexpected/missing issuer");
        assertThat(e.getMessage()).isEqualTo("JWT Claims validation failed");
    }


    @Test
    public void testProcessInvalidHmac() throws Exception {

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


        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(jwt));
        assertThat(e.getMessage()).isEqualTo("Signed JWT rejected: Invalid signature");
    }

    @Test
    @Disabled // FIXME Recreate jwt with correct JWE algorithm
    public void testProcessNestedJWT() throws Exception {

        // See http://tools.ietf.org/html/rfc7519#appendix-A.2

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

        JWTClaimsSet claims = processor.process(jwt);

        assertThat(claims.getIssuer()).isEqualTo("joe");
        assertThat(claims.getExpirationTime()).isNotNull();
        assertThat(claims.getExpirationTime().getTime()).isEqualTo(1300819380L * 1000L);
        assertThat(claims.getBooleanClaim("http://example.com/is_root")).isTrue();
        assertThat(claims.getClaims()).hasSize(3);
    }

    @Test
    public void testRejectPlain() throws Exception {

        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

        PlainJWT jwt = new PlainJWT(claims);

        try {
            new DefaultJWTProcessor().process(jwt);
        } catch (BadJOSEException e) {
            assertThat(e.getMessage()).isEqualTo("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
        }

        try {
            new DefaultJWTProcessor().process(jwt.serialize());
        } catch (BadJOSEException e) {
            assertThat(e.getMessage()).isEqualTo("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
        }
    }

    @Test
    public void testNoJWSKeyCandidates() throws Exception {

        // See http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        processor.setJWSKeySelector(new TestKeySelector(null));

        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(jws));
        assertThat(e.getMessage()).isEqualTo("Signed JWT rejected: Another algorithm expected, or no matching key(s) found");
    }

    @Test
    public void testNoJWEKeyCandidates()
            throws Exception {

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

        processor.setJWEKeySelector(new TestKeySelector(null));

        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(jwt));
        assertThat(e.getMessage()).isEqualTo("Encrypted JWT rejected: Another algorithm expected, or no matching key(s) found");
    }

    @Test
    public void testNoJWSKeySelector() throws Exception {

        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(jws));
        assertThat(e.getMessage()).isEqualTo("Signed JWT rejected: No JWS key selector is configured");
    }

    @Test
    public void testNoJWSFactory() throws Exception {

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

        JOSEException e = Assertions.assertThrows(JOSEException.class, () -> processor.process(jws));
        assertThat(e.getMessage()).isEqualTo("No JWS verifier is configured");

    }

    @Test
    public void testNoJWEKeySelector() throws Exception {

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

        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(jwe));

        assertThat(e.getMessage()).isEqualTo("Encrypted JWT rejected: No JWE key selector is configured");
    }

    @Test
    public void testNoJWEFactory() throws Exception {

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

        JOSEException e = Assertions.assertThrows(JOSEException.class, () -> processor.process(jwe));
        assertThat(e.getMessage()).isEqualTo("No JWE decrypter is configured");
    }

    @Test
    public void testJWTExpired() throws Exception {

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

        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> processor.process(jwt.serialize()));
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("Expired JWT");
        assertThat(e.getMessage()).isEqualTo("JWT Claims validation failed");
    }

    @Test
    public void testJWTBeforeUse()
            throws Exception {

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

        try {
            processor.process(jwt.serialize());
        } catch (BadJWTException e) {
            List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
            assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT before use time");

            assertThat(e.getMessage()).isEqualTo("JWT Claims validation failed");
        }
    }


    // Example for the WiKi
    @Test
    @Disabled
    public void testValidateJWTAccessToken() {

        /*
        // The access token to validate, typically submitted with a HTTP header like
        // Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3A...
        String accessToken =
                "eyJraWQiOiJDWHVwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJib2IiLCJzY" +
                        "3AiOlsib3BlbmlkIiwiZW1haWwiXSwiY2xtIjpbIiFCZyJdLCJpc3MiOiJodHRwczpcL1wvZGVtby5jM" +
                        "mlkLmNvbVwvYzJpZCIsImV4cCI6MTU3MTE3MTI2MiwiaWF0IjoxNTcxMTcwNjYyLCJ1aXAiOnsiZ3Jvd" +
                        "XBzIjpbImFkbWluIiwiYXVkaXQiXX0sImp0aSI6IllzcXZadE5fZFNRIiwiY2lkIjoiMDAwMTIzIn0.A" +
                        "99SrlpLmPxg_qttxsh2np_Czf9fJRIhMR90mwciPDsQLvswTTaLeK7jcAVXc_TYXaEuYOZQ1iXvxJMut" +
                        "pRZVUXvPjSQz1W4Ax-3w-zEZvgHRWtOQJgaj_XNGTkYV_2MeJDpW35eByAGPn8jDSRkapDVN-05rbuT5" +
                        "EZVmjpkJEsV1COqkgXx16J2OIswz13h2Pb9vyCwyspad6D6NW1z5ADjejqEb7Vf08XXAf4w_FbbekD76" +
                        "x6ToW-P-t6A17Mgy500C3Xq7ekZti8Tu1iz-KBVrH-R12rqPo3YGb98RraOUnYCg-2xDeriJsPmxkb6w" +
                        "omCTc141azPp6qIUiEfRw";

        // Create a JWT processor for the access tokens
        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also gracefully handle key-rollover
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL("https://demo.c2id.com/c2id/jwks.json"));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens
        DefaultJWTClaimsVerifier claimsVerifier = new DefaultJWTClaimsVerifier(
                null,
                new JWTClaimsSet.Builder().issuer("https://demo.c2id.com/c2id").build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp", "scp", "cid"))
        );
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());

         */
    }


    // iss178
    @Test
    @Disabled
    public void testGoogleIDToken() {

        /*
        // ID token from Google
        String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU3ZGJmNTI2ZjYzOWMyMTRjZDc3YjM5NmVjYjlkN2Y4MWQ0N2IzODIifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6ImdYM0ZJYzFxVUZzXy16RTNYYVMtZUEiLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI4OTY5MTg4OTk2MjY2OTEzNzQiLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0NjMxMzg2NDksImV4cCI6MTQ2MzE0MjI0OX0.GqQ0DPQQ5ixOGGAxcEu_5vqbMS7RyNzLrcn21AEid-61eQU0roq7gMVmCrTLeSghenNKNgFWQeErPe5i-6gxqV0r89dOdXRegpCLPAq7d-acPK_8bw-gOtbEo9Hhzcc56r51FwnZ3IUDgyKB_ZRNdp1LMnBgX--c6vPhy4_ZkVnJvmCzTz6bz-pdZNGFhtKd-xt35qVuyUok9tiGumKh-Tjrov5KPuZI90leRfLpoWDj_ktTClg3VUvXAtvDFhW94xEOS4s8DcvbxP9OrR3zhp4bgLohF-B0OrEqc9pTpYO87HyGJlvT74Re288tGZfCRJFX92BT1M063yt3QPrE8W";
        String jwkUri = "https://www.googleapis.com/oauth2/v3/certs";

        // Set up a JWT processor to parse the tokens and then check their signature
        // and validity time window (bounded by the "iat", "nbf" and "exp" claims)
        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also gracefully handle key-rollover
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwkUri));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(token, ctx);

        // Print out the token claims set
        System.out.println(claimsSet.toJSONObject());

         */
    }


    @Test
    public void testNestedWithMissingContentTypeHeader() throws Exception {

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

        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> proc.process(jwe));
        assertThat(e.getMessage()).isEqualTo("Payload of JWE object is not a valid JSON object");
    }


    @Test
    public void testNestedWithPlainJWT() throws Exception {

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


        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> proc.process(jwe));
        assertThat(e.getMessage()).isEqualTo("The payload is not a nested signed JWT");
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
    @Test
    public void testRejectPlainNestedJWT_noCTY()
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

        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> proc.process(jwe));
        assertThat(e.getMessage()).isEqualTo("Payload of JWE object is not a valid JSON object");
    }

    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
    @Test
    public void testRejectPlainNestedJWT_withCTY()
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

        BadJWTException e = Assertions.assertThrows(BadJWTException.class, () -> proc.process(jwe));
        assertThat(e.getMessage()).isEqualTo("The payload is not a nested signed JWT");
    }


    // issue https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/250/error-on-jwe-decryption-wrong-algorithm
    @Test
    public void testJCAKeyAlgAccepted()
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

        JWTClaimsSet outputClaimsSet = jwtProcessor.process((EncryptedJWT) jwt);

        assertThat(outputClaimsSet.getSubject()).isEqualTo(hostId);
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/257/error-on-jwe-decryption-with-aeskw
    @Test
    public void testJCAKeyAlgAccepted_AES_KW() throws Exception {

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

        assertThat(outputClaimsSet.getSubject()).isEqualTo("alice");
    }


    @Test
    public void testPlainJWT_noJWSTypeVerifier() {

        DefaultJWTProcessor processor = new DefaultJWTProcessor();

        BadJOSEException e = Assertions.assertThrows(BadJOSEException.class, () -> processor.process(new PlainJWT(new JWTClaimsSet.Builder().build())));
        assertThat(e.getMessage()).isEqualTo("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
    }



    private static class TestKeySelector extends KeySelector {
        private Key key;

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
            Assertions.assertDoesNotThrow(() -> {
                RSAKey jwkKey = RSAKey.parse(jwk);
                if (publicKey) {
                    key = jwkKey.toRSAPublicKey();
                } else {
                    key = jwkKey.toRSAPrivateKey();

                }
            });
        }

        @Override
        public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
            return (T) key;
        }
    }
}