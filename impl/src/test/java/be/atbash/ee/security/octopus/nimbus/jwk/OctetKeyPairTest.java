/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
import org.junit.Assert;
import org.junit.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class OctetKeyPairTest {


    // Test parameters are from JWK spec
    private static final class EXAMPLE_OKP_ED25519 {


        public static final Curve CRV = Curve.Ed25519;


        public static final Base64URLValue X = new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");


        public static final Base64URLValue D = new Base64URLValue("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    }


    private static final class EXAMPLE_OKP_X448 {

        public static final Curve CRV = Curve.X448;


        public static final Base64URLValue X = new Base64URLValue("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk");
    }


    @Test
    public void testParseRFCPrivateKeyExample()
            throws Exception {

        String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
                "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"," +
                "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assert.assertArrayEquals(okp.getX().decode(), okp.getDecodedX());
        assertThat(okp.getD()).isEqualTo(new Base64URLValue("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        Assert.assertArrayEquals(okp.getD().decode(), okp.getDecodedD());

        assertThat(okp.isPrivate()).isTrue();

        JWK pubJWK = okp.toPublicJWK();
        OctetKeyPair pubOKP = (OctetKeyPair) pubJWK;
        assertThat(pubOKP.getKeyType()).isEqualTo(KeyType.OKP);
        assertThat(pubOKP.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(pubOKP.getX()).isEqualTo(okp.getX());
        Assert.assertArrayEquals(okp.getX().decode(), pubOKP.getDecodedX());
        assertThat(pubOKP.getD()).isNull();
        assertThat(pubOKP.getDecodedD()).isNull();

        assertThat(pubOKP.isPrivate()).isFalse();
    }

    @Test
    public void testParseRFCPublicKeyExample()
            throws Exception {

        String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
                "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assert.assertArrayEquals(okp.getX().decode(), okp.getDecodedX());
        assertThat(okp.getD()).isNull();
        assertThat(okp.getDecodedD()).isNull();

        assertThat(okp.isPrivate()).isFalse();
    }

    @Test
    public void testThumbprintRFCExample()
            throws Exception {

        String json = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

        OctetKeyPair okp = OctetKeyPair.parse(json);

        assertThat(okp.getKeyType()).isEqualTo(KeyType.OKP);
        assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(okp.getX()).isEqualTo(new Base64URLValue("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        Assert.assertArrayEquals(okp.getX().decode(), okp.getDecodedX());
        assertThat(okp.getD()).isNull();
        assertThat(okp.getDecodedD()).isNull();

        assertThat(okp.isPrivate()).isFalse();

        assertThat(okp.computeThumbprint().toString()).isEqualTo("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    @Test
    public void testKeySizes() {

        assertThat(new OctetKeyPair.Builder(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X).build().size()).isEqualTo(256);
        assertThat(new OctetKeyPair.Builder(EXAMPLE_OKP_X448.CRV, EXAMPLE_OKP_X448.X).build().size()).isEqualTo(448);
    }

    @Test
    public void testSupportedCurvesConstant() {

        assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed25519)).isTrue();
        assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed448)).isTrue();
        assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X25519)).isTrue();
        assertThat(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X448)).isTrue();
        assertThat(OctetKeyPair.SUPPORTED_CURVES.size()).isEqualTo(4);
    }

    @Test
    public void testPrivateConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t = new Base64URLValue("abc");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;
        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D,
                KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t, x5t256, x5c, keyStore);

        assertThat(key instanceof AsymmetricJWK).isTrue();
        assertThat(key instanceof CurveBasedJWK).isTrue();

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        assertThat(key.getX509CertThumbprint().toString()).isEqualTo(x5t.toString());
        assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isEqualTo(keyStore);

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.D.decode(), key.getDecodedD());

        assertThat(key.isPrivate()).isTrue();

        JsonObject jsonObject = key.toJSONObject().build();
        assertThat(jsonObject.getString("crv")).isEqualTo(Curve.Ed25519.getName());
        assertThat(jsonObject.getString("x")).isEqualTo(EXAMPLE_OKP_ED25519.X.toString());
        assertThat(jsonObject.getString("d")).isEqualTo(EXAMPLE_OKP_ED25519.D.toString());

        String jwkString = jsonObject.toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyStore()).isNull();

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.D.decode(), key.getDecodedD());

        assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        assertThat(key.getX509CertThumbprint().toString()).isEqualTo(x5t.toString());
        assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isNull();

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isNull();
        assertThat(key.getDecodedD()).isNull();

        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testPublicConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t = new Base64URLValue("abc");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;
        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X,
                KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t, x5t256, x5c, keyStore);

        assertThat(key instanceof AsymmetricJWK).isTrue();
        assertThat(key instanceof CurveBasedJWK).isTrue();

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        assertThat(key.getX509CertThumbprint().toString()).isEqualTo(x5t.toString());
        assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isEqualTo(keyStore);

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isNull();
        assertThat(key.getDecodedD()).isNull();

        assertThat(key.isPrivate()).isFalse();

        JsonObject jsonObject = key.toJSONObject().build();
        assertThat(jsonObject.getString("crv")).isEqualTo(Curve.Ed25519.getName());
        assertThat(jsonObject.getString("x")).isEqualTo(EXAMPLE_OKP_ED25519.X.toString());
        assertThat(jsonObject.containsKey("d")).isFalse();

        String jwkString = jsonObject.toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isNull();
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyStore()).isNull();

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isNull();
        assertThat(key.getDecodedD()).isNull();

        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t = new Base64URLValue("abc");
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
                .x509CertThumbprint(x5t)
                .x509CertSHA256Thumbprint(x5tS256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL()).isEqualTo(x5u);
        assertThat(key.getX509CertThumbprint()).isEqualTo(x5t);
        assertThat(key.getX509CertSHA256Thumbprint()).isEqualTo(x5tS256);
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isEqualTo(keyStore);

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.D.decode(), key.getDecodedD());

        assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = OctetKeyPair.parse(jwkString);

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getKeyStore()).isNull();

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.D.decode(), key.getDecodedD());

        assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getKeyOperations()).isEqualTo(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)));
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL()).isEqualTo(x5u);
        assertThat(key.getX509CertThumbprint()).isEqualTo(x5t);
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isNull();

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isNull();
        assertThat(key.getDecodedD()).isNull();

        assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testCopyBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t = new Base64URLValue("abc");
        Base64URLValue x5tS256 = new Base64URLValue("ghi");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
                .d(EXAMPLE_OKP_ED25519.D)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertThumbprint(x5t)
                .x509CertSHA256Thumbprint(x5tS256)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Copy
        key = new OctetKeyPair.Builder(key).build();

        // Test getters
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.EdDSA);
        assertThat(key.getKeyID()).isEqualTo("1");
        assertThat(key.getX509CertURL()).isEqualTo(x5u);
        assertThat(key.getX509CertThumbprint()).isEqualTo(x5t);
        assertThat(key.getX509CertSHA256Thumbprint()).isEqualTo(x5tS256);
        assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        assertThat(key.getKeyStore()).isEqualTo(keyStore);

        assertThat(key.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(key.getX()).isEqualTo(EXAMPLE_OKP_ED25519.X);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.X.decode(), key.getDecodedX());
        assertThat(key.getD()).isEqualTo(EXAMPLE_OKP_ED25519.D);
        Assert.assertArrayEquals(EXAMPLE_OKP_ED25519.D.decode(), key.getDecodedD());

        assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testKeyIDFromThumbprint()
            throws Exception {

        OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
                .keyIDFromThumbprint()
                .build();

        assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    public void testRejectUnsupportedCurve() {

        for (Curve crv : new HashSet<>(Arrays.asList(Curve.P_256, Curve.P_384, Curve.P_521))) {

            // public OKP
            try {
                new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, null, null, null, null, null, null, null, null, null);
                fail();
            } catch (IllegalArgumentException e) {
                assertThat(e.getMessage()).isEqualTo("Unknown / unsupported curve: " + crv);
            }

            // public / private OKP
            try {
                new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D, null, null, null, null, null, null, null, null, null);
                fail();
            } catch (IllegalArgumentException e) {
                assertThat(e.getMessage()).isEqualTo("Unknown / unsupported curve: " + crv);
            }

            // builder
            try {
                new OctetKeyPair.Builder(crv, EXAMPLE_OKP_ED25519.X).build();
                fail();
            } catch (IllegalStateException e) {
                assertThat(e.getMessage()).isEqualTo("Unknown / unsupported curve: " + crv);
                assertThat(e.getCause() instanceof IllegalArgumentException).isTrue();
            }
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
        assertThat(okpB).isEqualTo(okpA);
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
        assertThat(okpA).isNotEqualTo(okpB);
    }
}
