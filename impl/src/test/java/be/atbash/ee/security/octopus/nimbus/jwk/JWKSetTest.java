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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JSON Web Key (JWK) set parsing and serialisation.
 *
 * Based on code by Vladimir Dzhuvinov and Vedran Pavic
 */
public class JWKSetTest {
    // FIXME, move over some of these test to KeyReader. Possibly add new methods.

    @Test
    public void testEmptyConstructor()
            throws ParseException {

        JWKSet jwkSet = new JWKSet();

        assertThat(jwkSet.getKeys().isEmpty()).isTrue();
        assertThat(jwkSet.getAdditionalMembers().isEmpty()).isTrue();

        String json = jwkSet.toJSONObject().toString();

        assertThat(json).isEqualTo("{\"keys\":[]}");

        jwkSet = JWKSet.parse(json);

        assertThat(jwkSet.getKeys().isEmpty()).isTrue();
        assertThat(jwkSet.getAdditionalMembers().isEmpty()).isTrue();
    }

    @Test
    public void testParsePublicJWKSet()
            throws Exception {

        // The string is from the JWK spec
        String json = "{\"keys\":" +
                "[" +
                "{\"kty\":\"EC\"," +
                "\"crv\":\"P-256\"," +
                "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                "\"use\":\"enc\"," +
                "\"kid\":\"1\"}," +
                " " +
                "{\"kty\":\"RSA\"," +
                "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
                "\"e\":\"AQAB\"," +
                "\"alg\":\"RS256\"," +
                "\"kid\":\"2011-04-29\"}" +
                "]" +
                "}";


        JWKSet keySet = JWKSet.parse(json);


        List<JWK> keyList = keySet.getKeys();
        assertThat(keyList.size()).isEqualTo(2);


        // Check first EC key
        JWK key = keyList.get(0);

        assertThat(key).isInstanceOf(ECKey.class);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

        ECKey ecKey = (ECKey) key;
        assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
        assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        assertThat(key.isPrivate()).isFalse();


        // Check second RSA key
        key = keyList.get(1);
        assertThat(key).isInstanceOf(RSAKey.class);
        assertThat(key.getKeyID()).isEqualTo("2011-04-29");
        assertThat(key.getKeyUse()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        RSAKey rsaKey = (RSAKey) key;
        assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testSerializeAndParsePublicJWKSet()
            throws Exception {

        ECParameterSpec ecParameterSpec = Curve.P_256.toECParameterSpec();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();

        ECKey ecKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES)
                .keyID("1234")
                .build();

        RSAKey rsaKey = new RSAKey.Builder(new Base64URLValue("abc"), new Base64URLValue("def"))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("5678")
                .build();

        Map<String, Object> additionalMembers = new HashMap<>();
        additionalMembers.put("setID", "xyz123");

        JWKSet keySet = new JWKSet(Arrays.asList(ecKey, rsaKey), additionalMembers);
        assertThat(keySet.getKeys().size()).isEqualTo(2);
        assertThat(keySet.getAdditionalMembers().size()).isEqualTo(1);

        String jwkSet = keySet.toString();

        keySet = JWKSet.parse(jwkSet);

        assertThat(keySet.getKeys().size()).isEqualTo(2);

        // Check first EC key
        ECKey ecKeyOut = (ECKey) keySet.getKeys().get(0);
        assertThat(ecKeyOut).isNotNull();
        assertThat(ecKeyOut.getCurve()).isEqualTo(Curve.P_256);
        assertThat(ecKeyOut.getX()).isEqualTo(ecKey.getX());
        assertThat(ecKeyOut.getY()).isEqualTo(ecKey.getY());
        assertThat(ecKeyOut.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(ecKeyOut.getKeyOperations()).isNull();
        assertThat(ecKeyOut.getAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(ecKeyOut.getKeyID()).isEqualTo("1234");

        // Check second RSA key
        RSAKey rsaKeyOut = (RSAKey) keySet.getKeys().get(1);
        assertThat(rsaKeyOut).isNotNull();
        assertThat(rsaKeyOut.getModulus().toString()).isEqualTo("abc");
        assertThat(rsaKeyOut.getPublicExponent().toString()).isEqualTo("def");
        assertThat(rsaKeyOut.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(rsaKeyOut.getKeyOperations()).isNull();
        assertThat(rsaKeyOut.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(rsaKeyOut.getKeyID()).isEqualTo("5678");

        // Check additional JWKSet members
        assertThat(keySet.getAdditionalMembers().size()).isEqualTo(1);
        assertThat((String) keySet.getAdditionalMembers().get("setID")).isEqualTo("xyz123");
    }

    @Test
    public void testParseOctetSequenceJWKSet()
            throws Exception {

        // The string is from the JPSK spec
        String json = "{\"keys\":" +
                "[" +
                " {\"kty\":\"oct\"," +
                "  \"alg\":\"A128KW\", " +
                "  \"k\":\"GawgguFyGrWKav7AX4VKUg\"}," +
                " {\"kty\":\"oct\", " +
                "  \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"," +
                "  \"kid\":\"HMAC key used in JWS A.1 example\"} " +
                "]" +
                "}";


        JWKSet keySet = JWKSet.parse(json);


        List<JWK> keyList = keySet.getKeys();
        assertThat(keyList.size()).isEqualTo(2);

        // First OCT key
        JWK key = keyList.get(0);
        assertThat(key).isInstanceOf(OctetSequenceKey.class);
        assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        assertThat(key.getKeyUse()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(key.getKeyID()).isNull();
        assertThat(((OctetSequenceKey) key).getKeyValue()).isEqualTo(new Base64URLValue("GawgguFyGrWKav7AX4VKUg"));

        // Second OCT key
        key = keyList.get(1);
        assertThat(key).isInstanceOf(OctetSequenceKey.class);
        assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        assertThat(key.getKeyUse()).isNull();
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isNull();
        assertThat(key.getKeyID()).isEqualTo("HMAC key used in JWS A.1 example");
        assertThat(((OctetSequenceKey) key).getKeyValue()).isEqualTo(new Base64URLValue("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"));
    }

    @Test
    public void testParsePrivateJWKSet() {

        // The string is from the JPSK spec
        String json = "{\"keys\":" +
                "  [" +
                "    {\"kty\":\"EC\"," +
                "     \"crv\":\"P-256\"," +
                "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
                "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
                "     \"use\":\"enc\"," +
                "     \"kid\":\"1\"}," +
                "" +
                "    {\"kty\":\"RSA\"," +
                "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
                "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
                "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
                "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
                "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
                "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
                "     \"e\":\"AQAB\"," +
                "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
                "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
                "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
                "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
                "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
                "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
                "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
                "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
                "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
                "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
                "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
                "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
                "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
                "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
                "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
                "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
                "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
                "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
                "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
                "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
                "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
                "     \"alg\":\"RS256\"," +
                "     \"kid\":\"2011-04-29\"}" +
                "  ]" +
                "}";


        Assertions.assertDoesNotThrow(() -> {
            JWKSet keySet = null;
            keySet = JWKSet.parse(json);


            List<JWK> keyList = keySet.getKeys();
            assertThat(keyList.size()).isEqualTo(2);


            // Check EC key
            JWK key = keyList.get(0);
            assertThat(key).isInstanceOf(ECKey.class);
            assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
            assertThat(key.getAlgorithm()).isNull();
            assertThat(key.getKeyID()).isEqualTo("1");

            ECKey ecKey = (ECKey) key;

            assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
            assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
            assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
            assertThat(ecKey.getD().toString()).isEqualTo("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");

            assertThat(ecKey.toPublicJWK().getD()).isNull();


            // Check RSA key
            key = keyList.get(1);
            assertThat(key).isInstanceOf(RSAKey.class);
            assertThat(key.getKeyUse()).isNull();
            assertThat(key.getKeyOperations()).isNull();
            assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
            assertThat(key.getKeyID()).isEqualTo("2011-04-29");

            RSAKey rsaKey = (RSAKey) key;

            assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");

            assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");


            assertThat(rsaKey.getPrivateExponent().toString()).isEqualTo("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
                    "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
                    "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
                    "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
                    "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
                    "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q");

            assertThat(rsaKey.getFirstPrimeFactor().toString()).isEqualTo("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
                    "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
                    "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs");

            assertThat(rsaKey.getSecondPrimeFactor().toString()).isEqualTo("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
                    "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
                    "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk");

            assertThat(rsaKey.getFirstFactorCRTExponent().toString()).isEqualTo("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
                    "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
                    "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0");

            assertThat(rsaKey.getSecondFactorCRTExponent().toString()).isEqualTo("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
                    "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
                    "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk");

            assertThat(rsaKey.getFirstCRTCoefficient().toString()).isEqualTo("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
                    "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
                    "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU");

            assertThat(rsaKey.getOtherPrimes().isEmpty()).isTrue();

            assertThat(rsaKey.toPublicJWK().getPrivateExponent()).isNull();
            assertThat(rsaKey.toPublicJWK().getFirstPrimeFactor()).isNull();
            assertThat(rsaKey.toPublicJWK().getSecondPrimeFactor()).isNull();
            assertThat(rsaKey.toPublicJWK().getFirstFactorCRTExponent()).isNull();
            assertThat(rsaKey.toPublicJWK().getSecondFactorCRTExponent()).isNull();
            assertThat(rsaKey.toPublicJWK().getFirstCRTCoefficient()).isNull();
            assertThat(rsaKey.toPublicJWK().getOtherPrimes().isEmpty()).isTrue();
        });
    }

    @Test
    public void testPublicJSONObjectSerialization()
            throws Exception {

        // The string is from the JPSK spec
        String json = "{\"keys\":" +
                "  [" +
                "    {\"kty\":\"EC\"," +
                "     \"crv\":\"P-256\"," +
                "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
                "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
                "     \"use\":\"enc\"," +
                "     \"kid\":\"1\"}," +
                "" +
                "    {\"kty\":\"RSA\"," +
                "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
                "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
                "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
                "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
                "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
                "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
                "     \"e\":\"AQAB\"," +
                "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
                "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
                "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
                "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
                "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
                "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
                "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
                "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
                "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
                "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
                "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
                "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
                "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
                "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
                "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
                "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
                "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
                "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
                "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
                "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
                "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
                "     \"alg\":\"RS256\"," +
                "     \"kid\":\"2011-04-29\"}" +
                "  ]" +
                "}";


        JWKSet keySet = JWKSet.parse(json);


        List<JWK> keyList = keySet.getKeys();
        assertThat(keyList.size()).isEqualTo(2);

        boolean publicParamsOnly = true;


        // Strip all private parameters
        json = keySet.toJSONObject(publicParamsOnly).toString();

        keySet = JWKSet.parse(json);

        keyList = keySet.getKeys();
        assertThat(keyList.size()).isEqualTo(2);

        // Check first EC key
        JWK key = keyList.get(0);

        assertThat(key).isInstanceOf(ECKey.class);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(key.getKeyOperations()).isNull();

        ECKey ecKey = (ECKey) key;
        assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
        assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        assertThat(key.isPrivate()).isFalse();


        // Check second RSA key
        key = keyList.get(1);
        assertThat(key).isInstanceOf(RSAKey.class);
        assertThat(key.getKeyID()).isEqualTo("2011-04-29");
        assertThat(key.getKeyUse()).isNull();
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        RSAKey rsaKey = (RSAKey) key;
        assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testGetByKeyId() throws Exception {
        // The string is from the JWK spec
        String json = "{\"keys\":" +
                "[" +
                "{\"kty\":\"EC\"," +
                "\"crv\":\"P-256\"," +
                "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                "\"use\":\"enc\"," +
                "\"kid\":\"1\"}," +
                " " +
                "{\"kty\":\"RSA\"," +
                "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
                "\"e\":\"AQAB\"," +
                "\"alg\":\"RS256\"," +
                "\"kid\":\"2011-04-29\"}" +
                "]" +
                "}";


        JWKSet keySet = JWKSet.parse(json);


        // Check first EC key
        JWK key = keySet.getKeyByKeyId("1");

        assertThat(key).isInstanceOf(ECKey.class);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

        ECKey ecKey = (ECKey) key;
        assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
        assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        assertThat(key.isPrivate()).isFalse();


        // Check second RSA key
        key = keySet.getKeyByKeyId("2011-04-29");
        assertThat(key).isInstanceOf(RSAKey.class);
        assertThat(key.getKeyID()).isEqualTo("2011-04-29");
        assertThat(key.getKeyUse()).isNull();
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        RSAKey rsaKey = (RSAKey) key;
        assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testOctJWKSetPublicExport()
            throws Exception {

        OctetSequenceKey oct1 = new OctetSequenceKey.Builder(new Base64URLValue("abc")).build();
        assertThat(oct1.getKeyValue().toString()).isEqualTo("abc");

        OctetSequenceKey oct2 = new OctetSequenceKey.Builder(new Base64URLValue("def")).build();
        assertThat(oct2.getKeyValue().toString()).isEqualTo("def");

        List<JWK> keyList = new LinkedList<>();
        keyList.add(oct1);
        keyList.add(oct2);

        JWKSet privateSet = new JWKSet(keyList);

        boolean publicParamsOnly = true;
        JsonObject jsonObject = privateSet.toJSONObject(publicParamsOnly);

        JWKSet publicSet = JWKSet.parse(jsonObject.toString());

        assertThat(publicSet.getKeys().size()).isEqualTo(0);
    }

    @Test
    public void testOctJWKSetToPublic() {

        OctetSequenceKey oct1 = new OctetSequenceKey.Builder(new Base64URLValue("abc")).build();
        assertThat(oct1.getKeyValue().toString()).isEqualTo("abc");

        OctetSequenceKey oct2 = new OctetSequenceKey.Builder(new Base64URLValue("def")).build();
        assertThat(oct2.getKeyValue().toString()).isEqualTo("def");

        List<JWK> keyList = new LinkedList<>();
        keyList.add(oct1);
        keyList.add(oct2);

        JWKSet privateSet = new JWKSet(keyList);

        JWKSet publicSet = privateSet.toPublicJWKSet();

        assertThat(publicSet.getKeys().size()).isEqualTo(0);
    }

    @Test
    public void testMIMEType() {

        assertThat(JWKSet.MIME_TYPE).isEqualTo("application/jwk-set+json; charset=UTF-8");
    }

	/*
	FIXME
	@Test
	public void testLoadFromInputStream()
		throws Exception {

		// The string is from the JWK spec
		String s = "{\"keys\":" +
				"[" +
				"{\"kty\":\"EC\"," +
				"\"crv\":\"P-256\"," +
				"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
				"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
				"\"use\":\"enc\"," +
				"\"kid\":\"1\"}," +
				" " +
				"{\"kty\":\"RSA\"," +
				"\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
				"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
				"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
				"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
				"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
				"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
				"\"e\":\"AQAB\"," +
				"\"alg\":\"RS256\"," +
				"\"kid\":\"2011-04-29\"}" +
				"]" +
				"}";

		ByteArrayInputStream inputStream = new ByteArrayInputStream(s.getBytes());

		JWKSet keySet = JWKSet.load(inputStream);


		List<JWK> keyList = keySet.getKeys();
		assertThat(keyList.size()).isEqualTo(2);


		// Check first EC key
		JWK key = keyList.get(0);

		assertThat(key instanceof ECKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("1");
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

		ECKey ecKey = (ECKey)key;
		assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
		assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
		assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
		assertThat(key.isPrivate()).isFalse();


		// Check second RSA key
		key = keyList.get(1);
		assertThat(key instanceof RSAKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("2011-04-29");
		assertThat(key.getKeyUse()).isNull();
		assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

		RSAKey rsaKey = (RSAKey)key;
		assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
				"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
				"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
				"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
				"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
				"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
		assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
		assertThat(key.isPrivate()).isFalse();
	}


	@Test
	public void testLoadFromFile()
		throws Exception {

		// The string is from the JWK spec
		String s = "{\"keys\":" +
			"[" +
			"{\"kty\":\"EC\"," +
			"\"crv\":\"P-256\"," +
			"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
			"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
			"\"use\":\"enc\"," +
			"\"kid\":\"1\"}," +
			" " +
			"{\"kty\":\"RSA\"," +
			"\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
			"\"e\":\"AQAB\"," +
			"\"alg\":\"RS256\"," +
			"\"kid\":\"2011-04-29\"}" +
			"]" +
			"}";

		File file = new File("TEST.jwkset.json");
		PrintWriter printWriter = new PrintWriter(file);
		printWriter.print(s);
		printWriter.close();

		JWKSet keySet = JWKSet.load(file);


		List<JWK> keyList = keySet.getKeys();
		assertThat(keyList.size()).isEqualTo(2);


		// Check first EC key
		JWK key = keyList.get(0);

		assertThat(key instanceof ECKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("1");
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

		ECKey ecKey = (ECKey)key;
		assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
		assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
		assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
		assertThat(key.isPrivate()).isFalse();


		// Check second RSA key
		key = keyList.get(1);
		assertThat(key instanceof RSAKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("2011-04-29");
		assertThat(key.getKeyUse()).isNull();
		assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

		RSAKey rsaKey = (RSAKey)key;
		assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
				"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
				"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
				"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
				"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
				"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
		assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
		assertThat(key.isPrivate()).isFalse();

		Files.delete(file.toPath());
	}

	@Test
	public void testLoadFromNonExistingFile()
		throws ParseException {
		
		try {
			JWKSet.load(new File("no-such-file"));
			fail();
		} catch (IOException e) {
			assertThat(e.getMessage()).isEqualTo("no-such-file (No such file or directory)");
		}
	}

	@Test
	public void testLoadFromURL()
		throws Exception {

		initJadler();

		// The string is from the JWK spec
		String s = "{\"keys\":" +
			"[" +
			"{\"kty\":\"EC\"," +
			"\"crv\":\"P-256\"," +
			"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
			"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
			"\"use\":\"enc\"," +
			"\"kid\":\"1\"}," +
			" " +
			"{\"kty\":\"RSA\"," +
			"\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
			"\"e\":\"AQAB\"," +
			"\"alg\":\"RS256\"," +
			"\"kid\":\"2011-04-29\"}" +
			"]" +
			"}";

		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withBody(s)
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("application/json");

		JWKSet keySet = JWKSet.load(new URL("http://localhost:" + port()));


		List<JWK> keyList = keySet.getKeys();
		assertThat(keyList.size()).isEqualTo(2);


		// Check first EC key
		JWK key = keyList.get(0);

		assertThat(key instanceof ECKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("1");
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

		ECKey ecKey = (ECKey)key;
		assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
		assertThat(ecKey.getX().toString()).isEqualTo("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
		assertThat(ecKey.getY().toString()).isEqualTo("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
		assertThat(key.isPrivate()).isFalse();


		// Check second RSA key
		key = keyList.get(1);
		assertThat(key instanceof RSAKey).isTrue();
		assertThat(key.getKeyID()).isEqualTo("2011-04-29");
		assertThat(key.getKeyUse()).isNull();
		assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

		RSAKey rsaKey = (RSAKey)key;
		assertThat(rsaKey.getModulus().toString()).isEqualTo("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
				"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
				"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
				"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
				"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
				"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
		assertThat(rsaKey.getPublicExponent().toString()).isEqualTo("AQAB");
		assertThat(key.isPrivate()).isFalse();

		closeJadler();
	}

	@Test
	public void testLoadFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// AES key
		KeyGenerator secGen = KeyGenerator.getInstance("AES");
		secGen.init(128);
		SecretKey secretKey = secGen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		// RSA key pair
		KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
		rsaGen.initialize(1024);
		KeyPair kp = rsaGen.generateKeyPair();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)kp.getPrivate();
		
		// Generate certificate
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			rsaPublicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(rsaPrivateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		keyStore.setKeyEntry("2", rsaPrivateKey, "".toCharArray(), new Certificate[]{cert});
		
		
		// EC key pair
		KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
		ecGen.initialize(Curve.P_521.toECParameterSpec());
		KeyPair ecKP = ecGen.generateKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey)ecKP.getPublic();
		ECPrivateKey ecPrivateKey = (ECPrivateKey)ecKP.getPrivate();
		
		// Generate certificate
		issuer = new X500Name("cn=c2id");
		serialNumber = new BigInteger(64, new SecureRandom());
		now = new Date();
		nbf = new Date(now.getTime() - 1000L);
		exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		subject = new X500Name("cn=c2id");
		x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			ecPublicKey
		);
		keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		certHolder = x509certBuilder.build(signerBuilder.build(ecPrivateKey));
		cert = X509CertUtils.parse(certHolder.getEncoded());
		keyStore.setKeyEntry("3", ecPrivateKey, "".toCharArray(), new Certificate[]{cert});
		
		
		
		// Load
		JWKSet jwkSet = JWKSet.load(keyStore, new PasswordLookup() {
			@Override
			public char[] lookupPassword(final String name) {
				if ("1".equalsIgnoreCase(name)) return "1234".toCharArray();
				else return "".toCharArray();
			}
		});
		
		
		OctetSequenceKey octJWK = (OctetSequenceKey) jwkSet.getKeyByKeyId("1");
		assertThat(octJWK).isNotNull();
		assertThat(octJWK.getKeyID()).isEqualTo("1");
		assertThat(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray())).isTrue();
		assertThat(octJWK.getKeyStore()).isEqualTo(keyStore);
		
		RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId("2");
		assertThat(rsaKey).isNotNull();
		assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(rsaKey.getKeyID()).isEqualTo("2");
		assertThat(rsaKey.getX509CertChain().size()).isEqualTo(1);
		assertThat(rsaKey.getX509CertThumbprint()).isNull();
		assertThat(rsaKey.getX509CertSHA256Thumbprint()).isNotNull();
		assertThat(rsaKey.isPrivate()).isTrue();
		assertThat(rsaKey.getKeyStore()).isEqualTo(keyStore);
		
		ECKey ecKey = (ECKey) jwkSet.getKeyByKeyId("3");
		assertThat(ecKey).isNotNull();
		assertThat(ecKey.getCurve()).isEqualTo(Curve.P_521);
		assertThat(ecKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(ecKey.getKeyID()).isEqualTo("3");
		assertThat(ecKey.getX509CertChain().size()).isEqualTo(1);
		assertThat(ecKey.getX509CertThumbprint()).isNull();
		assertThat(ecKey.getX509CertSHA256Thumbprint()).isNotNull();
		assertThat(ecKey.isPrivate()).isTrue();
		assertThat(ecKey.getKeyStore()).isEqualTo(keyStore);
		
		assertThat(jwkSet.getKeys().size()).isEqualTo(3);
	}

	 */

    @Test
    public void testImmutableKeyList() {

        JWKSet jwkSet = new JWKSet();

        try {
            jwkSet.getKeys().add(new RSAKey.Builder(new Base64URLValue("abc"), new Base64URLValue("def"))
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID("5678")
                    .build());
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isNull();
        }
    }

    @Test
    public void testImmutableAdditionalTopLevelParams() {

        JWKSet jwkSet = new JWKSet();

        try {
            jwkSet.getAdditionalMembers().put("key", "value");
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isNull();
        }
    }

    @Test
    public void testParse_missingKeysField() {

        ParseException e = Assertions.assertThrows(ParseException.class,
                () -> JWKSet.parse("{}"));
        assertThat(e.getMessage()).isEqualTo("Missing required \"keys\" member");
    }

    @Test
    public void getAtbashKeys() {
        List<AtbashKey> atbashKeys = generateRSAKeys("kid");
        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = null;
        for (AtbashKey atbashKey : atbashKeys) {
            if (atbashKey.getKey() instanceof RSAPrivateKey) {
                privateKey = (RSAPrivateKey) atbashKey.getKey();
            }
            if (atbashKey.getKey() instanceof RSAPublicKey) {
                publicKey = (RSAPublicKey) atbashKey.getKey();
            }
        }

        RSAKey rsaKey = new RSAKey(publicKey, privateKey, KeyUse.SIGNATURE, null, null, "kid", null, null, null, null);
        JWKSet jwkSet = new JWKSet(rsaKey);

        List<AtbashKey> keys = jwkSet.getAtbashKeys();

        assertThat(keys).hasSize(2);
    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }
}
