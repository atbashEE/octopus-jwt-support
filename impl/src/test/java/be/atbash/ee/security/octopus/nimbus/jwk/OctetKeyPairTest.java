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


import be.atbash.ee.security.octopus.nimbus.SampleCertificates;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import java.net.URI;
import java.security.KeyStore;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public class OctetKeyPairTest {


    // Test parameters are from JWK spec
    private static final class EXAMPLE_OKP_ED25519 {

        static final Curve CRV = Curve.Ed25519;


        static final Base64URLValue X = new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");


        static final Base64URLValue D = new Base64URLValue("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    }


    private static final class EXAMPLE_OKP_X448 {

        static final Curve CRV = Curve.X448;


        static final Base64URLValue X = new Base64URLValue("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk");
    }


    @Test
    public void testParseRFCPrivateKeyExample()
            throws Exception {

        String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
                "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"," +
                "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        Assertions.assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        Assertions.assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assertions.assertThat(okp.getDecodedX()).isEqualTo(okp.getX().decode());
        Assertions.assertThat(okp.getD()).isEqualTo(new Base64URLValue("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        Assertions.assertThat(okp.getDecodedD()).isEqualTo(okp.getD().decode());

        Assertions.assertThat(okp.isPrivate()).isTrue();

        OctetKeyPair pubOKP = okp.toPublicJWK();
        Assertions.assertThat(pubOKP.getKeyType()).isEqualTo(KeyType.OKP);
        Assertions.assertThat(pubOKP.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(pubOKP.getX()).isEqualTo(okp.getX());
        Assertions.assertThat(pubOKP.getDecodedX()).isEqualTo(okp.getX().decode());
        Assertions.assertThat(pubOKP.getD()).isNull();
        Assertions.assertThat(pubOKP.getDecodedD()).isNull();

        Assertions.assertThat(pubOKP.isPrivate()).isFalse();
    }

    @Test
    public void testParseRFCPublicKeyExample()
            throws Exception {

        String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
                "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        Assertions.assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        Assertions.assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assertions.assertThat(okp.getDecodedX()).isEqualTo(okp.getX().decode());
        Assertions.assertThat(okp.getD()).isNull();
        Assertions.assertThat(okp.getDecodedD()).isNull();

        Assertions.assertThat(okp.isPrivate()).isFalse();
    }

    @Test
    public void testThumbprintRFCExample()
            throws Exception {

        String json = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        Assertions.assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        Assertions.assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assertions.assertThat(okp.getDecodedX()).isEqualTo(okp.getX().decode());
        Assertions.assertThat(okp.getD()).isNull();
        Assertions.assertThat(okp.getDecodedD()).isNull();

        Assertions.assertThat(okp.isPrivate()).isFalse();

        Assertions.assertThat(okp.computeThumbprint().toString()).isEqualTo("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    @Test
    public void testKeySizes() {

        Assertions.assertThat(new OctetKeyPair.Builder(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X).build().size()).isEqualTo(256);
        Assertions.assertThat(new OctetKeyPair.Builder(EXAMPLE_OKP_X448.CRV, EXAMPLE_OKP_X448.X).build().size()).isEqualTo(448);
    }

    @Test
    public void testSupportedCurvesConstant() {

        Assertions.assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed25519)).isTrue();
        Assertions.assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed448)).isTrue();
        Assertions.assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X25519)).isTrue();
        Assertions.assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X448)).isTrue();
        Assertions.assertThat(OctetKeyPair.SUPPORTED_CURVES.size()).isEqualTo(4);
    }

    @Test
    public void testPrivateConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;
        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D,
                KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t256, x5c, keyStore);

        Assertions.assertThat(key).isInstanceOf(AsymmetricJWK.class);
        Assertions.assertThat(key).isInstanceOf(CurveBasedJWK.class);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assertions.assertThat(key.getDecodedD()).isEqualTo(EXAMPLE_OKP_ED25519.D.decode());

        Assertions.assertThat(key.isPrivate()).isTrue();

        JsonObject jsonObject = key.toJSONObject().build();
        Assertions.assertThat(jsonObject.getString("crv")).isEqualTo(Curve.Ed25519.getName());
        Assertions.assertThat(jsonObject.getString("x")).isEqualTo(EXAMPLE_OKP_ED25519.X.toString());
        Assertions.assertThat(jsonObject.getString("d")).isEqualTo(EXAMPLE_OKP_ED25519.D.toString());

        String jwkString = jsonObject.toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assertions.assertThat(key.getDecodedD()).isEqualTo(EXAMPLE_OKP_ED25519.D.decode());

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isNull();
        Assertions.assertThat(key.getDecodedD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testPublicConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;
        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X,
                KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t256, x5c, keyStore);

        Assertions.assertThat(key).isInstanceOf(AsymmetricJWK.class);
        Assertions.assertThat(key).isInstanceOf(CurveBasedJWK.class);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isNull();
        Assertions.assertThat(key.getDecodedD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();

        JsonObject jsonObject = key.toJSONObject().build();
        Assertions.assertThat(jsonObject.getString("crv")).isEqualTo(Curve.Ed25519.getName());
        Assertions.assertThat(jsonObject.getString("x")).isEqualTo(EXAMPLE_OKP_ED25519.X.toString());
        Assertions.assertThat(jsonObject.containsKey("d")).isFalse();

        String jwkString = jsonObject.toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isNull();
        Assertions.assertThat(key.getDecodedD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5tS256 = new Base64URLValue("ghi");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
                .d(EXAMPLE_OKP_ED25519.D)
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)))
                .algorithm(JWSAlgorithm.EdDSA)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertSHA256Thumbprint(x5tS256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL()).isEqualTo(x5u);
        Assertions.assertThat(key.getX509CertSHA256Thumbprint()).isEqualTo(x5tS256);
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assertions.assertThat(key.getDecodedD()).isEqualTo(EXAMPLE_OKP_ED25519.D.decode());

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assertions.assertThat(key.getDecodedD()).isEqualTo(EXAMPLE_OKP_ED25519.D.decode());

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL()).isEqualTo(x5u);
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isNull();
        Assertions.assertThat(key.getDecodedD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testCopyBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5tS256 = new Base64URLValue("ghi");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
                .d(EXAMPLE_OKP_ED25519.D)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertSHA256Thumbprint(x5tS256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Copy
        key = new OctetKeyPair.Builder(key).build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL()).isEqualTo(x5u);
        Assertions.assertThat(key.getX509CertSHA256Thumbprint()).isEqualTo(x5tS256);
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        Assertions.assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assertions.assertThat(key.getDecodedX()).isEqualTo(EXAMPLE_OKP_ED25519.X.decode());
        Assertions.assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assertions.assertThat(key.getDecodedD()).isEqualTo(EXAMPLE_OKP_ED25519.D.decode());

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testKeyIDFromThumbprint() {

        OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
                .keyIDFromThumbprint()
                .build();

        Assertions.assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    public void testRejectUnsupportedCurve() {

        for (Curve crv : new HashSet<>(Arrays.asList(Curve.P_256, Curve.P_384, Curve.P_521))) {

            // public OKP
            Assertions.assertThatThrownBy(
                            () -> new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, null, null, null, null, null, null, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown / unsupported curve: " + crv);

            // public / private OKP
            Assertions.assertThatThrownBy(
                            () -> new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D, null, null, null, null, null, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown / unsupported curve: " + crv);

            // builder
            Assertions.assertThatThrownBy(
                            () -> new OctetKeyPair.Builder(crv, EXAMPLE_OKP_ED25519.X).build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Unknown / unsupported curve: " + crv);

        }
    }

    @Test
    public void testEqualsSuccess()
            throws Exception {

        //Given
        String json = "{\n" +
                "    \"kty\" : \"OKP\",\n" +
                "    \"crv\" : \"Ed25519\",\n" +
                "    \"x\"   : \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\n" +
                "    \"d\"   : \"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\n" +
                "    \"use\" : \"sig\",\n" +
                "    \"kid\" : \"1\"\n" +
                "  }";

        OctetKeyPair okpA = OctetKeyPair.parse(json);
        OctetKeyPair okpB = OctetKeyPair.parse(json);

        //When

        //Then
        Assertions.assertThat(okpB).isEqualTo(okpA);
    }

    @Test
    public void testEqualsFailure()
            throws Exception {

        //Given
        String jsonA = "{\n" +
                "    \"kty\" : \"OKP\",\n" +
                "    \"crv\" : \"Ed25519\",\n" +
                "    \"x\"   : \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\n" +
                "    \"d\"   : \"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\n" +
                "    \"use\" : \"sig\",\n" +
                "    \"kid\" : \"1\"\n" +
                "  }";

        OctetKeyPair okpA = OctetKeyPair.parse(jsonA);

        String jsonB = "{\n" +
                "    \"kty\" : \"OKP\",\n" +
                "    \"crv\" : \"Ed25519\",\n" +
                "    \"x\"   : \"ewrewrewrw\",\n" +
                "    \"d\"   : \"werewrwerw\",\n" +
                "    \"use\" : \"sig\",\n" +
                "    \"kid\" : \"1\"\n" +
                "  }";

        OctetKeyPair okpB = OctetKeyPair.parse(jsonB);

        //When

        //Then
        Assertions.assertThat(okpA).isNotEqualTo(okpB);
    }

    @Test
    public void testParse_fromEmptyJSONObject() {

        JsonObject jsonObject = Json.createObjectBuilder().build();
        Assertions.assertThatThrownBy(
                        () -> OctetKeyPair.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key type to parse must not be null");

    }

    @Test
    public void testParse_missingKty() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.CURVE, "Ed25519")
                .add(JWKIdentifiers.X_COORD, "ewrewrewr")
                .build();

        Assertions.assertThatThrownBy(
                        () -> OctetKeyPair.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key type to parse must not be null");

    }

    @Test
    public void testParse_missingCrv() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "OKP")
                .add(JWKIdentifiers.X_COORD, "ewrewrewr")
                .build();

        Assertions.assertThatThrownBy(
                        () -> OctetKeyPair.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The cryptographic curve string must not be null or empty");

    }


    @Test
    public void testParse_missingX() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "OKP")
                .add(JWKIdentifiers.CURVE, "Ed25519")
                .build();

        Assertions.assertThatThrownBy(
                        () -> OctetKeyPair.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The 'x' parameter must not be null");

    }
}
