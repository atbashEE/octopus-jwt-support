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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.IOUtil;
import be.atbash.ee.security.octopus.nimbus.SampleCertificates;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.X509CertChainUtils;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

/**
 * Tests the RSA JWK class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class RSAKeyTest {


    // Test parameters are from JPSK spec


    private static final String n =
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";


    private static final String e = "AQAB";


    private static final String d =
            "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
                    "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
                    "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
                    "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
                    "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
                    "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";


    private static final String p =
            "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
                    "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
                    "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";


    private static final String q =
            "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
                    "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
                    "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";


    private static final String dp =
            "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
                    "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
                    "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";


    private static final String dq =
            "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
                    "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
                    "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";


    private static final String qi =
            "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
                    "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
                    "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";


    @Test
    public void testConstructAndSerialize()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null; // not specified here

        // Recreate PrivateKey
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(new RSAPrivateKeySpec(new Base64URLValue(n).decodeToBigInteger(), new Base64URLValue(d).decodeToBigInteger()));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        RSAKey key = new RSAKey(new Base64URLValue(n), new Base64URLValue(e), new Base64URLValue(d),
                new Base64URLValue(p), new Base64URLValue(q),
                new Base64URLValue(dp), new Base64URLValue(dq), new Base64URLValue(qi), null,
                privateKey,
                KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
                x5u, x5t256, x5c,
                keyStore);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        // private key generated from key material, not PrivateKey ref
        Assertions.assertThat(key.toPrivateKey()).isNotSameAs(privateKey);

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = RSAKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isNull();

        Assertions.assertThat(key.getFirstPrimeFactor()).isNull();
        Assertions.assertThat(key.getSecondPrimeFactor()).isNull();

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isNull();
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isNull();

        Assertions.assertThat(key.getFirstCRTCoefficient()).isNull();

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testConstructorAndSerialize()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null; // not specified here

        RSAKey key = new RSAKey(new Base64URLValue(n), new Base64URLValue(e), new Base64URLValue(d),
                new Base64URLValue(p), new Base64URLValue(q),
                new Base64URLValue(dp), new Base64URLValue(dq), new Base64URLValue(qi),
                null, null,
                KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
                x5u, x5t256, x5c, null);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = RSAKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isNull();

        Assertions.assertThat(key.getFirstPrimeFactor()).isNull();
        Assertions.assertThat(key.getSecondPrimeFactor()).isNull();

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isNull();
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isNull();

        Assertions.assertThat(key.getFirstCRTCoefficient()).isNull();

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testBase64Builder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc");
        List<Base64Value> x5c = null; // not specified here

        RSAKey key = new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                .privateExponent(new Base64URLValue(d))
                .firstPrimeFactor(new Base64URLValue(p))
                .secondPrimeFactor(new Base64URLValue(q))
                .firstFactorCRTExponent(new Base64URLValue(dp))
                .secondFactorCRTExponent(new Base64URLValue(dq))
                .firstCRTCoefficient(new Base64URLValue(qi))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertSHA256Thumbprint(x5t256)
                .x509CertChain(x5c)
                .build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = RSAKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testObjectBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null; // not specified here

        Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        RSAKey key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(null)
                .keyOperations(ops)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertSHA256Thumbprint(x5t256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger())).isTrue();
        Assertions.assertThat(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger())).isTrue();

        Assertions.assertThat(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger())).isTrue();

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = RSAKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger())).isTrue();
        Assertions.assertThat(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger())).isTrue();

        Assertions.assertThat(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger())).isTrue();

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testCopyBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null; // not specified here

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        RSAKey key = new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                .privateExponent(new Base64URLValue(d))
                .firstPrimeFactor(new Base64URLValue(p))
                .secondPrimeFactor(new Base64URLValue(q))
                .firstFactorCRTExponent(new Base64URLValue(dp))
                .secondFactorCRTExponent(new Base64URLValue(dq))
                .firstCRTCoefficient(new Base64URLValue(qi))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertSHA256Thumbprint(x5t256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Copy
        key = new RSAKey.Builder(key).build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testRSAPublicKeyExportAndImport() {


        RSAKey key = new RSAKey(new Base64URLValue(n), new Base64URLValue(e),
                new Base64URLValue(d), null, null, null,
                null, null, null, null, null);

        // Public key export
        RSAPublicKey pubKey = key.toRSAPublicKey();
        Assertions.assertThat(pubKey.getModulus()).isEqualTo(new Base64URLValue(n).decodeToBigInteger());
        Assertions.assertThat(pubKey.getPublicExponent()).isEqualTo(new Base64URLValue(e).decodeToBigInteger());
        Assertions.assertThat(pubKey.getAlgorithm()).isEqualTo("RSA");


        // Public key import
        key = new RSAKey(pubKey, null, null, null, null, null, null, null, null);
        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));
    }

    @Test
    public void testRSAPrivateKeyExportAndImport() {

        RSAKey key = new RSAKey(new Base64URLValue(n), new Base64URLValue(e), new Base64URLValue(d),
                new Base64URLValue(p), new Base64URLValue(q),
                new Base64URLValue(dp), new Base64URLValue(dq), new Base64URLValue(qi),
                null, null, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
                null, null, null, null);

        // Private key export with CRT (2nd form)
        RSAPrivateKey privKey = key.toRSAPrivateKey();
        Assertions.assertThat(privKey).isNotNull();

        Assertions.assertThat(privKey.getModulus()).isEqualTo(new Base64URLValue(n).decodeToBigInteger());
        Assertions.assertThat(privKey.getPrivateExponent()).isEqualTo(new Base64URLValue(d).decodeToBigInteger());

        Assertions.assertThat(privKey).isInstanceOf(RSAPrivateCrtKey.class);
        RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey) privKey;
        Assertions.assertThat(privCrtKey.getPublicExponent()).isEqualTo(new Base64URLValue(e).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeP()).isEqualTo(new Base64URLValue(p).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeQ()).isEqualTo(new Base64URLValue(q).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeExponentP()).isEqualTo(new Base64URLValue(dp).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeExponentQ()).isEqualTo(new Base64URLValue(dq).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getCrtCoefficient()).isEqualTo(new Base64URLValue(qi).decodeToBigInteger());


        // Key pair export
        KeyPair pair = key.toKeyPair();

        RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
        Assertions.assertThat(pubKey.getModulus()).isEqualTo(new Base64URLValue(n).decodeToBigInteger());
        Assertions.assertThat(pubKey.getPublicExponent()).isEqualTo(new Base64URLValue(e).decodeToBigInteger());
        Assertions.assertThat(pubKey.getAlgorithm()).isEqualTo("RSA");

        privKey = (RSAPrivateKey) pair.getPrivate();
        Assertions.assertThat(privKey.getModulus()).isEqualTo(new Base64URLValue(n).decodeToBigInteger());
        Assertions.assertThat(privKey.getPrivateExponent()).isEqualTo(new Base64URLValue(d).decodeToBigInteger());

        Assertions.assertThat(privKey).isInstanceOf(RSAPrivateCrtKey.class);
        privCrtKey = (RSAPrivateCrtKey) privKey;
        Assertions.assertThat(privCrtKey.getPublicExponent()).isEqualTo(new Base64URLValue(e).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeP()).isEqualTo(new Base64URLValue(p).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeQ()).isEqualTo(new Base64URLValue(q).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeExponentP()).isEqualTo(new Base64URLValue(dp).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getPrimeExponentQ()).isEqualTo(new Base64URLValue(dq).decodeToBigInteger());
        Assertions.assertThat(privCrtKey.getCrtCoefficient()).isEqualTo(new Base64URLValue(qi).decodeToBigInteger());


        // Key pair import, 1st private form
        key = new RSAKey(pubKey, privKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null, null);
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isNull();
        Assertions.assertThat(key.getSecondPrimeFactor()).isNull();

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isNull();
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isNull();

        Assertions.assertThat(key.getFirstCRTCoefficient()).isNull();

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Key pair import, 2nd private form
        key = new RSAKey(pubKey, privCrtKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null, null, null);
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");

        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));

        Assertions.assertThat(key.getPrivateExponent()).isEqualTo(new Base64URLValue(d));

        Assertions.assertThat(key.getFirstPrimeFactor()).isEqualTo(new Base64URLValue(p));
        Assertions.assertThat(key.getSecondPrimeFactor()).isEqualTo(new Base64URLValue(q));

        Assertions.assertThat(key.getFirstFactorCRTExponent()).isEqualTo(new Base64URLValue(dp));
        Assertions.assertThat(key.getSecondFactorCRTExponent()).isEqualTo(new Base64URLValue(dq));

        Assertions.assertThat(key.getFirstCRTCoefficient()).isEqualTo(new Base64URLValue(qi));

        Assertions.assertThat(key.getOtherPrimes().isEmpty()).isTrue();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testPublicKeyExportAndImport() {


        RSAKey key = new RSAKey(new Base64URLValue(n), new Base64URLValue(e),
                new Base64URLValue(d), null, null, null,
                null, null, null, null, null);

        Assertions.assertThat(key).isInstanceOf(AsymmetricJWK.class);

        // Public key export
        RSAPublicKey pubKey = (RSAPublicKey) key.toPublicKey();
        Assertions.assertThat(pubKey.getModulus()).isEqualTo(new Base64URLValue(n).decodeToBigInteger());
        Assertions.assertThat(pubKey.getPublicExponent()).isEqualTo(new Base64URLValue(e).decodeToBigInteger());
        Assertions.assertThat(pubKey.getAlgorithm()).isEqualTo("RSA");


        // Public key import
        key = new RSAKey(pubKey, null, null, null, null, null, null, null, null);
        Assertions.assertThat(key.getModulus()).isEqualTo(new Base64URLValue(n));
        Assertions.assertThat(key.getPublicExponent()).isEqualTo(new Base64URLValue(e));
    }

    @Test
    public void testParseSomeKey()
            throws Exception {

        String json = "{\n" +
                "      \"kty\": \"RSA\",\n" +
                "      \"n\": \"f9BhJgBgoDKGcYLh-xl6qulS8fUFYxuWSz4Sk-7Yw2Wv4Wroe3yLzJjqEqH8IFR0Ow8Sr3pZo0IwOPcWHQZMQr0s2kWbKSpBrnDsK4vsdBvoP1jOaylA9XsHPF9EZ_1F-eQkVHoMsc9eccf0nmr3ubD56LjSorTsbOuxi8nqEzisvhDHthacW_qxbpR_jojQNfdWyDz6NC-MA2LYYpdsw5TG8AVdKjobHWfQvXYdcpvQRkDDhgbwQt1KD8ZJ1VL-nJcIfSppPzCbfM2eY78y_c4euL_SQPs7kGf-u3R9hden7FjMUuIFZoAictiBgjVZ_JOaK-C--L-IsnCKqauhEQ==\",\n" +
                "      \"e\": \"AQAB\",\n" +
                "      \"alg\": \"RS256\"\n" +
                "}";

        RSAKey key = RSAKey.parse(json);

        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(key.getModulus().decode().length).isEqualTo(256);
    }

    @Test
    public void testKeyConversionRoundTrip()
            throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.genKeyPair();
        RSAPublicKey rsaPublicKeyIn = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKeyIn = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaJWK = new RSAKey.Builder(rsaPublicKeyIn).privateKey(rsaPrivateKeyIn).build();

        // Compare JWK values with original Java RSA values
        Assertions.assertThat(rsaJWK.getPublicExponent().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaJWK.getModulus().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getModulus());
        Assertions.assertThat(rsaJWK.getPrivateExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());

        // Convert back to Java RSA keys
        RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
        RSAPrivateKey rsaPrivateKeyOut = rsaJWK.toRSAPrivateKey();
        Assertions.assertThat(rsaPrivateKeyOut).isNotNull();

        Assertions.assertThat(rsaPublicKeyOut.getAlgorithm()).isEqualTo(rsaPublicKeyIn.getAlgorithm());
        Assertions.assertThat(rsaPublicKeyOut.getPublicExponent()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaPublicKeyOut.getModulus()).isEqualTo(rsaPublicKeyIn.getModulus());

        Assertions.assertThat(rsaPrivateKeyOut.getAlgorithm()).isEqualTo(rsaPrivateKeyIn.getAlgorithm());
        Assertions.assertThat(rsaPrivateKeyOut.getPrivateExponent()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());

        // Compare encoded forms
        Assertions.assertThat(Base64Value.encode(rsaPublicKeyOut.getEncoded()).toString()).withFailMessage("Public RSA").isEqualTo(Base64Value.encode(rsaPublicKeyIn.getEncoded()).toString());
        Assertions.assertThat(Base64Value.encode(rsaPrivateKeyOut.getEncoded()).toString()).withFailMessage("Private RSA").isEqualTo(Base64Value.encode(rsaPrivateKeyIn.getEncoded()).toString());

        RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

        // Compare JWK values with original Java RSA values
        Assertions.assertThat(rsaJWK2.getPublicExponent().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaJWK2.getModulus().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getModulus());
        Assertions.assertThat(rsaJWK2.getPrivateExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());
    }

    @Test
    public void testKeyConversionRoundTripWithCRTParams()
            throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.genKeyPair();
        RSAPublicKey rsaPublicKeyIn = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateCrtKey rsaPrivateKeyIn = (RSAPrivateCrtKey) keyPair.getPrivate();

        RSAKey rsaJWK = new RSAKey(rsaPublicKeyIn, rsaPrivateKeyIn, null, null, null, null, null, null, null, null, null);

        // Compare JWK values with original Java RSA values
        Assertions.assertThat(rsaJWK.getPublicExponent().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaJWK.getModulus().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getModulus());
        Assertions.assertThat(rsaJWK.getPrivateExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());

        // Compare CRT params
        Assertions.assertThat(rsaJWK.getFirstPrimeFactor().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeP());
        Assertions.assertThat(rsaJWK.getSecondPrimeFactor().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeQ());
        Assertions.assertThat(rsaJWK.getFirstFactorCRTExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentP());
        Assertions.assertThat(rsaJWK.getSecondFactorCRTExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentQ());
        Assertions.assertThat(rsaJWK.getFirstCRTCoefficient().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getCrtCoefficient());
        Assertions.assertThat(rsaJWK.getOtherPrimes() == null || rsaJWK.getOtherPrimes().isEmpty()).isTrue();

        // Convert back to Java RSA keys
        RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
        RSAPrivateCrtKey rsaPrivateKeyOut = (RSAPrivateCrtKey) rsaJWK.toRSAPrivateKey();
        Assertions.assertThat(rsaPrivateKeyOut).isNotNull();

        Assertions.assertThat(rsaPublicKeyOut.getAlgorithm()).isEqualTo(rsaPublicKeyIn.getAlgorithm());
        Assertions.assertThat(rsaPublicKeyOut.getPublicExponent()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaPublicKeyOut.getModulus()).isEqualTo(rsaPublicKeyIn.getModulus());

        Assertions.assertThat(rsaPrivateKeyOut.getAlgorithm()).isEqualTo(rsaPrivateKeyIn.getAlgorithm());
        Assertions.assertThat(rsaPrivateKeyOut.getPrivateExponent()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());

        Assertions.assertThat(rsaPrivateKeyOut.getPrimeP()).isEqualTo(rsaPrivateKeyIn.getPrimeP());
        Assertions.assertThat(rsaPrivateKeyOut.getPrimeQ()).isEqualTo(rsaPrivateKeyIn.getPrimeQ());
        Assertions.assertThat(rsaPrivateKeyOut.getPrimeExponentP()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentP());
        Assertions.assertThat(rsaPrivateKeyOut.getPrimeExponentQ()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentQ());
        Assertions.assertThat(rsaPrivateKeyOut.getCrtCoefficient()).isEqualTo(rsaPrivateKeyIn.getCrtCoefficient());

        // Compare encoded forms
        Assertions.assertThat(Base64Value.encode(rsaPublicKeyOut.getEncoded()).toString()).withFailMessage("Public RSA").isEqualTo(Base64Value.encode(rsaPublicKeyIn.getEncoded()).toString());
        Assertions.assertThat(Base64Value.encode(rsaPrivateKeyOut.getEncoded()).toString()).withFailMessage("Private RSA").isEqualTo(Base64Value.encode(rsaPrivateKeyIn.getEncoded()).toString());

        RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

        // Compare JWK values with original Java RSA values
        Assertions.assertThat(rsaJWK2.getPublicExponent().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getPublicExponent());
        Assertions.assertThat(rsaJWK2.getModulus().decodeToBigInteger()).isEqualTo(rsaPublicKeyIn.getModulus());
        Assertions.assertThat(rsaJWK2.getPrivateExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrivateExponent());

        // Compare CRT params
        Assertions.assertThat(rsaJWK2.getFirstPrimeFactor().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeP());
        Assertions.assertThat(rsaJWK2.getSecondPrimeFactor().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeQ());
        Assertions.assertThat(rsaJWK2.getFirstFactorCRTExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentP());
        Assertions.assertThat(rsaJWK2.getSecondFactorCRTExponent().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getPrimeExponentQ());
        Assertions.assertThat(rsaJWK2.getFirstCRTCoefficient().decodeToBigInteger()).isEqualTo(rsaPrivateKeyIn.getCrtCoefficient());
        Assertions.assertThat(rsaJWK2.getOtherPrimes() == null || rsaJWK2.getOtherPrimes().isEmpty()).isTrue();
    }

    @Test
    public void testKeyUseConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        JWK jwk = new RSAKey(new Base64URLValue(n), new Base64URLValue(e), new Base64URLValue(d), use, ops, null, null, null, null, null, null);
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(use);
        Assertions.assertThat(jwk.getKeyOperations()).isEqualTo(ops);

        jwk = new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                .keyUse(use)
                .keyOperations(ops)
                .build();
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(use);
        Assertions.assertThat(jwk.getKeyOperations()).isEqualTo(ops);

        // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/226/jwk-constructor-erroneously-throws
        ops = Collections.singleton(KeyOperation.SIGN);
        jwk = new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                .privateExponent(new Base64URLValue(d))
                .keyUse(use)
                .keyOperations(ops)
                .build();
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(use);
        Assertions.assertThat(jwk.getKeyOperations()).isEqualTo(ops);
    }

    @Test
    public void testRejectKeyUseNotConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT));

        try {
            new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                    .keyUse(use)
                    .keyOperations(ops)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The key use \"use\" and key options \"key_opts\" parameters are not consistent, see RFC 7517, section 4.3");
        }
    }

    @Test
    public void testRejectEmptyCertificateChain() {

        try {
            new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e))
                    .x509CertChain(Collections.emptyList())
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The X.509 certificate chain \"x5c\" must not be empty");
        }
    }

    @Test
    public void testParseCookbookExample()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7520#section-3.4

        String json = "{" +
                "\"kty\": \"RSA\"," +
                "\"kid\": \"bilbo.baggins@hobbiton.example\"," +
                "\"use\": \"sig\"," +
                "\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
                "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
                "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
                "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
                "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
                "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
                "HdrNP5zw\"," +
                "\"e\": \"AQAB\"," +
                "\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
                "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
                "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
                "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
                "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
                "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
                "OpBrQzwQ\"," +
                "\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
                "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
                "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
                "bUq0k\"," +
                "\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
                "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
                "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
                "s7pFc\"," +
                "\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
                "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
                "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
                "59ehik\"," +
                "\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
                "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
                "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
                "T1cYF8\"," +
                "\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
                "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
                "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
                "z8aaI4\"" +
                "}";

        RSAKey jwk = RSAKey.parse(json);

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("bilbo.baggins@hobbiton.example");
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);

        Assertions.assertThat(jwk.getModulus().toString()).isEqualTo("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
                "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
                "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
                "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
                "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
                "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
                "HdrNP5zw");

        Assertions.assertThat(jwk.getPublicExponent().toString()).isEqualTo("AQAB");

        Assertions.assertThat(jwk.getPrivateExponent().toString()).isEqualTo("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
                "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
                "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
                "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
                "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
                "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
                "OpBrQzwQ");

        Assertions.assertThat(jwk.getFirstPrimeFactor().toString()).isEqualTo("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
                "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
                "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
                "bUq0k");

        Assertions.assertThat(jwk.getSecondPrimeFactor().toString()).isEqualTo("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
                "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
                "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
                "s7pFc");

        Assertions.assertThat(jwk.getFirstFactorCRTExponent().toString()).isEqualTo("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
                "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
                "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
                "59ehik");

        Assertions.assertThat(jwk.getSecondFactorCRTExponent().toString()).isEqualTo("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
                "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
                "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
                "T1cYF8");

        Assertions.assertThat(jwk.getFirstCRTCoefficient().toString()).isEqualTo("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
                "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
                "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
                "z8aaI4");

        // Convert to Java RSA key object
        RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
        RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

        jwk = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

        Assertions.assertThat(jwk.getModulus().toString()).isEqualTo("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
                "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
                "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
                "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
                "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
                "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
                "HdrNP5zw");

        Assertions.assertThat(jwk.getPublicExponent().toString()).isEqualTo("AQAB");

        Assertions.assertThat(jwk.getPrivateExponent().toString()).isEqualTo("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
                "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
                "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
                "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
                "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
                "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
                "OpBrQzwQ");
    }

    @Test
    public void testParseCookbookExample2()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7520#section-5.1.1

        String json = "{" +
                "\"kty\":\"RSA\"," +
                "\"kid\":\"frodo.baggins@hobbiton.example\"," +
                "\"use\":\"enc\"," +
                "\"n\":\"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
                "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
                "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
                "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
                "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
                "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
                "VotGlvMQ\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
                "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
                "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
                "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
                "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
                "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
                "pzj85bQQ\"," +
                "\"p\":\"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
                "oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
                "7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
                "2VFmU\"," +
                "\"q\":\"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
                "F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
                "9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
                "d6Et0\"," +
                "\"dp\":\"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
                "QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
                "RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
                "lo0rYU\"," +
                "\"dq\":\"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
                "pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
                "CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
                "TkXlHE\"," +
                "\"qi\":\"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
                "lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
                "Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
                "2bQ_mM\"" +
                "}";

        RSAKey jwk = RSAKey.parse(json);

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("frodo.baggins@hobbiton.example");
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);

        Assertions.assertThat(jwk.getModulus().toString()).isEqualTo("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
                "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
                "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
                "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
                "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
                "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
                "VotGlvMQ");

        Assertions.assertThat(jwk.getPublicExponent().toString()).isEqualTo("AQAB");

        Assertions.assertThat(jwk.getPrivateExponent().toString()).isEqualTo("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
                "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
                "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
                "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
                "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
                "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
                "pzj85bQQ");

        Assertions.assertThat(jwk.getFirstPrimeFactor().toString()).isEqualTo("2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
                "oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
                "7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
                "2VFmU");

        Assertions.assertThat(jwk.getSecondPrimeFactor().toString()).isEqualTo("te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
                "F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
                "9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
                "d6Et0");

        Assertions.assertThat(jwk.getFirstFactorCRTExponent().toString()).isEqualTo("UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
                "QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
                "RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
                "lo0rYU");

        Assertions.assertThat(jwk.getSecondFactorCRTExponent().toString()).isEqualTo("iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
                "pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
                "CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
                "TkXlHE");

        Assertions.assertThat(jwk.getFirstCRTCoefficient().toString()).isEqualTo("kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
                "lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
                "Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
                "2bQ_mM");

        // Convert to Java RSA key object
        RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
        RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

        jwk = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

        Assertions.assertThat(jwk.getModulus().toString()).isEqualTo("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
                "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
                "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
                "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
                "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
                "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
                "VotGlvMQ");

        Assertions.assertThat(jwk.getPublicExponent().toString()).isEqualTo("AQAB");

        Assertions.assertThat(jwk.getPrivateExponent().toString()).isEqualTo("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
                "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
                "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
                "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
                "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
                "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
                "pzj85bQQ");
    }

    @Test
    // Test vector from https://tools.ietf.org/html/rfc7638#section-3.1
    public void testComputeThumbprint()
            throws Exception {

        String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
                "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
                "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
                "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
                "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

        RSAKey rsaKey = RSAKey.parse(json);

        Base64URLValue thumbprint = rsaKey.computeThumbprint();

        Assertions.assertThat(rsaKey.computeThumbprint("SHA-256")).isEqualTo(thumbprint);

        Assertions.assertThat(thumbprint.toString()).isEqualTo("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        Assertions.assertThat(thumbprint.decode().length).isEqualTo(256 / 8);
    }

    @Test
    public void testComputeThumbprintSHA1()
            throws Exception {

        String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
                "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
                "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
                "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
                "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

        RSAKey rsaKey = RSAKey.parse(json);

        Base64URLValue thumbprint = rsaKey.computeThumbprint("SHA-1");

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(160 / 8);
    }

    @Test
    // Test vector from https://tools.ietf.org/html/rfc7638#section-3.1
    public void testThumbprintAsKeyID()
            throws Exception {

        String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
                "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
                "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
                "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
                "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

        RSAKey rsaKey = RSAKey.parse(json);

        rsaKey = new RSAKey.Builder(rsaKey.getModulus(), rsaKey.getPublicExponent())
                .keyIDFromThumbprint()
                .build();

        Assertions.assertThat(rsaKey.getKeyID()).isEqualTo("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    @Test
    public void testThumbprintSHA1AsKeyID()
            throws Exception {

        String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
                "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
                "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
                "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
                "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

        RSAKey rsaKey = RSAKey.parse(json);

        rsaKey = new RSAKey.Builder(rsaKey.getModulus(), rsaKey.getPublicExponent())
                .keyIDFromThumbprint("SHA-1")
                .build();

        Assertions.assertThat(new Base64URLValue(rsaKey.getKeyID()).decode().length).isEqualTo(160 / 8);
    }

    @Test
    public void testSize() {

        Assertions.assertThat(new RSAKey.Builder(new Base64URLValue(n), new Base64URLValue(e)).build().size()).isEqualTo(2048);
    }

    @Test
    // For private RSA keys as PKCS#11 handle
    public void testPrivateKeyHandle()
            throws Exception {

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        KeyPair kp = gen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        PrivateKey privateKey = new PrivateKey() {
            // simulate private PKCS#11 key with inaccessible key material
            @Override
            public String getAlgorithm() {
                return kp.getPrivate().getAlgorithm();
            }


            @Override
            public String getFormat() {
                return kp.getPrivate().getFormat();
            }


            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        RSAKey rsaJWK = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("1")
                .build();

        Assertions.assertThat(rsaJWK.toPublicKey()).isNotNull();
        Assertions.assertThat(rsaJWK.toPrivateKey()).isEqualTo(privateKey);
        Assertions.assertThat(rsaJWK.isPrivate()).isTrue();

        KeyPair kpOut = rsaJWK.toKeyPair();
        Assertions.assertThat(kpOut.getPublic()).isNotNull();
        Assertions.assertThat(kpOut.getPrivate()).isEqualTo(privateKey);

        JsonObject json = rsaJWK.toJSONObject().build();
        Assertions.assertThat(json.getString(JWKIdentifiers.KEY_TYPE)).isEqualTo("RSA");
        Assertions.assertThat(json.getString("kid")).isEqualTo("1");
        Assertions.assertThat(json.getString("e")).isEqualTo(Base64URLValue.encode(publicKey.getPublicExponent()).toString());
        Assertions.assertThat(json.getString("n")).isEqualTo(Base64URLValue.encode(publicKey.getModulus()).toString());
        Assertions.assertThat(json).hasSize(4);
    }

    @Test
    public void testParseFromX509Cert()
            throws Exception {

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();
        RSAKey rsaKey = RSAKey.parse(cert);

        Assertions.assertThat(rsaKey.getKeyUse()).isNull();
        Assertions.assertThat(rsaKey.getKeyID()).isEqualTo(cert.getSerialNumber().toString(10));
        Assertions.assertThat(rsaKey.getX509CertChain().get(0).toString()).isNotSameAs(pemEncodedCert);
        Assertions.assertThat(rsaKey.getX509CertChain()).hasSize(1);
        Assertions.assertThat(rsaKey.getX509CertSHA256Thumbprint()).isEqualTo(Base64URLValue.encode(sha256.digest(cert.getEncoded())));
        Assertions.assertThat(rsaKey.getAlgorithm()).isNull();
        Assertions.assertThat(rsaKey.getKeyOperations()).isNull();
    }

    @Test
    public void testParseFromX509CertWithECPublicKey() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();

        Assertions.assertThatThrownBy(
                        () -> RSAKey.parse(cert))
                .isInstanceOf(JOSEException.class)
                .hasMessage("The public key of the X.509 certificate is not RSA");
    }

    @Test
    public void testX509CertificateChain()
            throws Exception {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);

        RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();
        Base64URLValue n = Base64URLValue.encode(rsaPublicKey.getModulus());
        Base64URLValue e = Base64URLValue.encode(rsaPublicKey.getPublicExponent());

        RSAKey jwk = new RSAKey.Builder(n, e)
                .x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
                .build();

        Assertions.assertThat(jwk.getX509CertChain().get(0)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(0));
        Assertions.assertThat(jwk.getX509CertChain().get(1)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(1));
        Assertions.assertThat(jwk.getX509CertChain().get(2)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(2));

        String json = jwk.toJSONString();

        jwk = RSAKey.parse(json);

        Assertions.assertThat(jwk.getX509CertChain().get(0)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(0));
        Assertions.assertThat(jwk.getX509CertChain().get(1)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(1));
        Assertions.assertThat(jwk.getX509CertChain().get(2)).isEqualTo(SampleCertificates.SAMPLE_X5C_RSA.get(2));
    }

    @Test
    public void testX509CertificateChain_algDoesntMatch() {
        try {
            new RSAKey.Builder(
                    new Base64URLValue(n),
                    new Base64URLValue(e)
            )
                    .x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
        }
    }

    @Test
    public void testX509CertificateChain_modulusDoesntMatch()
            throws Exception {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);

        RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();

        try {
            new RSAKey.Builder(
                    new Base64URLValue(n), // other mod
                    Base64URLValue.encode(rsaPublicKey.getPublicExponent())
            )
                    .x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
        }
    }

    @Test
    public void testX509CertificateChain_exponentDoesntMatch()
            throws Exception {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);

        RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();

        try {
            new RSAKey.Builder(
                    Base64URLValue.encode(rsaPublicKey.getModulus()),
                    new Base64URLValue("AAAA") // other exp
            )
                    .x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
        }
    }

    @Test
    public void testLoadFromKeyStore()
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
        RSAKey rsaKey = RSAKey.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(rsaKey).isNotNull();
        Assertions.assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(rsaKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(rsaKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(rsaKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(rsaKey.isPrivate()).isTrue();
        Assertions.assertThat(rsaKey.getKeyStore()).isEqualTo(keyStore);

        // Try to load with bad pin
        Assertions.assertThatThrownBy(
                        () -> RSAKey.load(keyStore, "1", "".toCharArray()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't retrieve private RSA key (bad pin?): Cannot recover key");

    }

    @Test
    public void testLoadFromKeyStore_publicKeyOnly()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);

        keyStore.setCertificateEntry("1", cert);

        RSAKey rsaKey = RSAKey.load(keyStore, "1", null);
        Assertions.assertThat(rsaKey).isNotNull();
        Assertions.assertThat(rsaKey.getKeyUse()).isNull();
        Assertions.assertThat(rsaKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(rsaKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(rsaKey.getParsedX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(rsaKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(rsaKey.isPrivate()).isFalse();
        Assertions.assertThat(rsaKey.getKeyStore()).isEqualTo(keyStore);
    }

    @Test
    public void testLoadFromKeyStore_notRSA()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);

        keyStore.setCertificateEntry("1", cert);

        Assertions.assertThatThrownBy(
                        () -> RSAKey.load(keyStore, "1", null))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't load RSA JWK: The key algorithm is not RSA");
    }

    @Test
    public void testLoadFromKeyStore_notFound()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        Assertions.assertThat(RSAKey.load(keyStore, "1", null)).isNull();
    }

    @Test
    public void testEqualsSuccess()
            throws Exception {

        //Given
        String json = "{   \"kty\" : \"RSA\",\n" +
                "   \"n\"   : \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\n" +
                "            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\n" +
                "            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\n" +
                "            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\n" +
                "            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\n" +
                "            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "   \"e\"   : \"AQAB\",\n" +
                "   \"d\"   : \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\n" +
                "            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\n" +
                "            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\n" +
                "            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\n" +
                "            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\n" +
                "            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\n" +
                "   \"p\"   : \"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\n" +
                "            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\n" +
                "            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\n" +
                "   \"q\"   : \"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\n" +
                "            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\n" +
                "            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\n" +
                "   \"dp\"  : \"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\n" +
                "            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\n" +
                "            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\n" +
                "   \"dq\"  : \"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\n" +
                "            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\n" +
                "            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\n" +
                "   \"qi\"  : \"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\n" +
                "            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\n" +
                "            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\n" +
                "   \"alg\" : \"RS256\",\n" +
                "   \"kid\" : \"2011-04-29\"\n" +
                " }";
        RSAKey keyA = RSAKey.parse(json.replaceAll("\n", ""));
        RSAKey keyB = RSAKey.parse(json.replaceAll("\n", ""));

        //When

        //Then
        Assertions.assertThat(keyB).isEqualTo(keyA);
    }

    @Test
    public void testEqualsFailure()
            throws Exception {

        //Given
        String jsonA = "{   \"kty\" : \"RSA\",\n" +
                "   \"n\"   : \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\n" +
                "            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\n" +
                "            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\n" +
                "            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\n" +
                "            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\n" +
                "            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "   \"e\"   : \"AQAB\",\n" +
                "   \"d\"   : \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\n" +
                "            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\n" +
                "            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\n" +
                "            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\n" +
                "            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\n" +
                "            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\n" +
                "   \"p\"   : \"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\n" +
                "            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\n" +
                "            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\n" +
                "   \"q\"   : \"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\n" +
                "            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\n" +
                "            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\n" +
                "   \"dp\"  : \"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\n" +
                "            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\n" +
                "            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\n" +
                "   \"dq\"  : \"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\n" +
                "            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\n" +
                "            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\n" +
                "   \"qi\"  : \"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\n" +
                "            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\n" +
                "            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\n" +
                "   \"alg\" : \"RS256\",\n" +
                "   \"kid\" : \"2011-04-29\"\n" +
                " }";
        RSAKey keyA = RSAKey.parse(jsonA.replaceAll("\n", ""));

        String jsonB = "{\n" +
                "      \"kty\": \"RSA\",\n" +
                "      \"d\": \"Y03dVLbCCgWpiZnzUyT1E_JuQkM9-Kl9ice2Yp_8ex-ywZHF1GvYYBsKyKjAf3o_dua5XX9IDILK2TJZ2uhWefaEPMhh1OL4rveEoq4-jU3kdax-_8WJ8r-gatoUXl-IyDePiMZGgd4uTLzqF752-qtPEBmbfQK7ndP1z6h5t2fUA-h_Z6DIXuguci-2I_mDu9QA4tRUdwClDRVY8J6tNj8YhZiz6xdtCkbDeonDTvOGmmDJNStkp4WVzpE_D09cudLMAz8_g2_y6j_Jq6EGhrVLP85JEfJI3YBpGGgOdQMRIqm0xp8xjY9Pz5bIc3yCbpWV2FeJyk3eKXtQCpSPgQ\",\n" +
                "      \"e\": \"AQAB\",\n" +
                "      \"n\": \"w1-xUupu_rLsGPUaFYk0ZYhMNhWQ-scT4DlNPvuPDV2ocfWe1Jl2kuOz0o_UKmmSCMsTDZ2IzT79gJL2qCcNGwFsXOcgvaUYxM2HUF7QP6rM9afLhyHR99m4t1sptfXlLUqNPYC2iexH_HVzabaokyRfKxiFKFs-L1Jns1HddkkWbATCnRAEMOMAqtFRLNwpX4qtEfENie7DCMZE6Sjz-grz4Z1f7-AzIvW3EzNOpxYZcLONfFC0iyLHIadcMln73pb7iXUKGLdvFcmtEmSoF6KfrC1SM_s_02NtaIFXzKhVG4c-1iBijhTprPC3Q4Q6cEKLROAyGnrsAg6ByzlsNQ\",\n" +
                "      \"alg\" : \"RS256\",\n" +
                "      \"kid\" : \"2011-04-29\"\n" +
                "    }";
        RSAKey keyB = RSAKey.parse(jsonB.replaceAll("\n", ""));

        //When

        //Then
        Assertions.assertThat(keyA).isNotSameAs(keyB);

    }

    @Test
    public void testRSAKeyRoundtripWithX5c() throws Exception {

        RSAKey rsaKey = RSAKey.parse(
                "{\"kty\":\"RSA\",\"x5t#S256\":\"QOjjUwPhfMBMIT2zn5nrUxc4GocujsSHziKh-FlvmiU\",\"e\":\"AQAB\",\"kid\":\"18031265869169735523\",\"x5c\":[\"MIIDljCCAn4CCQD6O+zGNny3YzANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMCQkUxEDAOBgNVBAgTB0JlbGdpdW0xETAPBgNVBAcTCEJydXNzZWxzMRwwGgYDVQQKExNFdXJvcGVhbiBDb21taXNzaW9uMRAwDgYDVQQLEwdTRkMyMDE0MR8wHQYDVQQDExZTRkMyMDE0IENBIERFVkVMT1BNRU5UMSAwHgYJKoZIhvcNAQkBFhF2YW53b2JlQHlhaG9vLkNvbTAeFw0xNjEwMTgxNTE4NTdaFw0yNjEwMTYxNTE4NTdaMHQxCzAJBgNVBAYTAkJFMRAwDgYDVQQIEwdCRUxHSVVNMREwDwYDVQQHEwhCcnVzc2VsczEcMBoGA1UEChMTRXVyb3BlYW4gQ29tbWlzc2lvbjEQMA4GA1UECxMHU0ZDMjAxNDEQMA4GA1UEAxMHdmFud29iZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMC7n95a0Yp\\/anE2ya3VhUjJ8KhoC8mAiblGJYMPsB2QfLKJEoZ2eSCD\\/GwkxufEb8UPauQDFogMshUZwwZ08k0OXywh3a9xO9zI+CCz23TNvueACQzWbtwWrx6lU5ljOOhBdt+c\\/CRXXgG2kH+hhs8MaV5KgN6iPf0HilH3QP2pwLNVLrupm\\/0r9CwuEc\\/wWLbi1nLno366vn\\/+jdsuxSrWnr\\/S8SCY3+L6CzZfhWMzF1SrsiCn+v6MirAwcG2IckNomGiL+X7PjObOSIWDVa7G9\\/Ouh4EaZN0w\\/zUvMSZ8mXkTo\\/Qk48kQlzm\\/KoQpEcoa9Dng4EdGyXzsipxsCNsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAlBtx8Lh3PL1PBoiki5VkPUqfNlYNE6C+3faPzjEKu0D8+g\\/y1AbFp7442J3QqX0yfS\\/qG3BIc2dU8ICDhmstn7d2yr+FDFF4raQ8OfMocQy66Rf6wgAQy0YETWF+gBx8bKhd3D+V12paZg8ocDE7+V0UOCmxRMSz8hRvycCYGlf5pD2v2DIfPatNgwyASZK+qu+w++OrilC3wXKG2XD8AWaoTWMWz1ycov6pSnRGEr0DNxF4DBWrJWe\\/b+HH1K1hiKG0lnD520Ldoy3VRF86uRBnAjKX0yy7LHZy1QaB6M5DHtzOQFg7GldjhuZVFA01smyadepiOI0jc6jTwghT2Q==\"],\"n\":\"wLuf3lrRin9qcTbJrdWFSMnwqGgLyYCJuUYlgw-wHZB8sokShnZ5IIP8bCTG58RvxQ9q5AMWiAyyFRnDBnTyTQ5fLCHdr3E73Mj4ILPbdM2-54AJDNZu3BavHqVTmWM46EF235z8JFdeAbaQf6GGzwxpXkqA3qI9_QeKUfdA_anAs1Uuu6mb_Sv0LC4Rz_BYtuLWcuejfrq-f_6N2y7FKtaev9LxIJjf4voLNl-FYzMXVKuyIKf6_oyKsDBwbYhyQ2iYaIv5fs-M5s5IhYNVrsb3866HgRpk3TD_NS8xJnyZeROj9CTjyRCXOb8qhCkRyhr0OeDgR0bJfOyKnGwI2w\"}");

        JsonObject jsonObject = rsaKey.toJSONObject().build();
        JsonArray x5cArray = (JsonArray) jsonObject.get(JWKIdentifiers.X_509_CERT_CHAIN);
        Assertions.assertThat(x5cArray.getString(0)).isEqualTo(rsaKey.getX509CertChain().get(0).toString());
        Assertions.assertThat(x5cArray).hasSize(1);

        // Fails with java.text.ParseException: Unexpected type of JSON object member with key "x5c"
        RSAKey secondPassKey = RSAKey.parse(rsaKey.toJSONObject().build());

        Assertions.assertThat(rsaKey).isEqualTo(secondPassKey);
    }

    @Test
    public void testBuilderWithAtbashKey() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        RSAKey rsaKey = new RSAKey.Builder(publicKey.get(0)).build();
        Assertions.assertThat(rsaKey).isNotNull();
    }

    @Test
    public void testBuilderWithAtbashKey_WrongType() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);

        Assertions.assertThatThrownBy(
                        () -> new RSAKey.Builder(publicKey.get(0)).build())
                .isInstanceOf(KeyTypeException.class)
                .hasMessage("PUBLIC key required for RSAKey creation");

    }

    @Test
    public void testBuilderWithAtbashKey_WrongKey() {
        List<AtbashKey> keys = TestKeys.generateECKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);

        Assertions.assertThatThrownBy(
                        () -> new RSAKey.Builder(publicKey.get(0)).build())
                .isInstanceOf(KeyTypeException.class)
                .hasMessage("Unsupported KeyType EC for RSAKey creation");

    }
}
