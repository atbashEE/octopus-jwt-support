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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.*;


/**
 * Tests the EC JWK class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class ECKeyTest {


    // Test parameters are from JWK spec
    private static final class ExampleKeyP256 {

        static final Curve CRV = Curve.P_256;

        static final Base64URLValue X = new Base64URLValue("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");

        static final Base64URLValue Y = new Base64URLValue("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");

        static final Base64URLValue D = new Base64URLValue("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
    }

    // Test parameters are from Anders Rundgren, public only
    private static final class ExampleKeyP256Alt {

        static final Curve CRV = Curve.P_256;

        static final Base64URLValue X = new Base64URLValue("3l2Da_flYc-AuUTm2QzxgyvJxYM_2TeB9DMlwz7j1PE");

        static final Base64URLValue Y = new Base64URLValue("-kjT7Wrfhwsi9SG6H4UXiyUiVE9GHCLauslksZ3-_t0");
    }

    // Test parameters are from Anders Rundgren, public only
    private static final class ExampleKeyP384Alt {

        static final Curve CRV = Curve.P_384;

        static final Base64URLValue X = new Base64URLValue("Xy0mn0LmRyDBeHBjZrqH9z5Weu5pzCZYl1FJGHdoEj1utAoCpD4-Wn3VAIT-qgFF");

        static final Base64URLValue Y = new Base64URLValue("mrZQ1aB1E7JksXe6LXmM3BiGzqtlwCtMN0cpJb5EU62JMSISSK8l7cXSFt84A25z");
    }

    // Test parameters are from Anders Rundgren, public only
    private static final class ExampleKeyP521Alt {

        static final Curve CRV = Curve.P_521;

        static final Base64URLValue X = new Base64URLValue("AfwEaSkqoPQynn4SdAXOqbyDuK6KsbI04i-6aWvh3GdvREZuHaWFyg791gcvJ4OqG13-gzfYxZxfblPMqfOtQrzk");

        static final Base64URLValue Y = new Base64URLValue("AHgOZhhJb2ZiozkquiEa0Z9SfERJbWaaE7qEnCuk9VVZaWruKWKNzZadoIRPt8h305r14KRoxu8AfV20X-d_2Ups");
    }

    @Test
    public void testKeySizes() {

        Assertions.assertThat(new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build().size()).isEqualTo(256);
        Assertions.assertThat(new ECKey.Builder(ExampleKeyP256Alt.CRV, ExampleKeyP256Alt.X, ExampleKeyP256Alt.Y).build().size()).isEqualTo(256);
        Assertions.assertThat(new ECKey.Builder(ExampleKeyP384Alt.CRV, ExampleKeyP384Alt.X, ExampleKeyP384Alt.Y).build().size()).isEqualTo(384);
        Assertions.assertThat(new ECKey.Builder(ExampleKeyP521Alt.CRV, ExampleKeyP521Alt.X, ExampleKeyP521Alt.Y).build().size()).isEqualTo(521);
    }

    @Test
    public void testSupportedCurvesConstant() {

        Assertions.assertThat(ECKey.SUPPORTED_CURVES).containsOnly(Curve.P_256,
                Curve.P_256K, Curve.SECP256K1, Curve.P_384, Curve.P_521);

    }

    @Test
    public void testUnknownCurve() {

        Assertions.assertThatThrownBy(() -> new ECKey.Builder(new Curve("unknown"), ExampleKeyP256.X, ExampleKeyP256.Y).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Unknown / unsupported curve: unknown");

    }

    @Test
    public void testAltECKeyParamLengths() {

        Assertions.assertThat(ExampleKeyP256Alt.X.decode().length).isEqualTo(32);
        Assertions.assertThat(ExampleKeyP256Alt.Y.decode().length).isEqualTo(32);

        Assertions.assertThat(ExampleKeyP384Alt.X.decode().length).isEqualTo(48);
        Assertions.assertThat(ExampleKeyP384Alt.Y.decode().length).isEqualTo(48);

        Assertions.assertThat(ExampleKeyP521Alt.X.decode().length).isEqualTo(66);
        Assertions.assertThat(ExampleKeyP521Alt.Y.decode().length).isEqualTo(66);
    }

    @Test
    public void testCoordinateEncoding() {

        byte[] unpadded = {1, 2, 3, 4, 5};
        BigInteger bigInteger = new BigInteger(1, unpadded);

        // With no padding required
        int fieldSize = unpadded.length * 8;
        Assertions.assertThat(ECKey.encodeCoordinate(fieldSize, bigInteger)).isEqualTo(Base64URLValue.encode(unpadded));

        // With two leading zeros padding required
        fieldSize = unpadded.length * 8 + 2 * 8;
        Assertions.assertThat(ECKey.encodeCoordinate(fieldSize, bigInteger)).isEqualTo(Base64URLValue.encode(new byte[]{0, 0, 1, 2, 3, 4, 5}));
        Assertions.assertThat(ECKey.encodeCoordinate(fieldSize, bigInteger).decodeToBigInteger().toString()).isEqualTo(bigInteger.toString());
    }

    @Test
    public void testFullPrivateConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null;

        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
                KeyUse.SIGNATURE, ops, JWSAlgorithm.ES256, "1", x5u, x5t256, x5c, keyStore);

        Assertions.assertThat(key).isInstanceOf(AsymmetricJWK.class);
        Assertions.assertThat(key).isInstanceOf(CurveBasedJWK.class);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = ECKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testPrivateConstructorAndSerializationWithOps()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = null;

        KeyUse use = null;
        Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        ECKey key = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, ExampleKeyP256.D,
                use, ops, JWSAlgorithm.ES256, "1", x5u, x5t256, x5c, null);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = ECKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        List<Base64Value> x5c = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        ECKey key = new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
                .d(ExampleKeyP256.D)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = ECKey.parse(jwkString);

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();


        // Test conversion to public JWK

        key = key.toPublicJWK();

        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isNull();

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testCopyBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        List<Base64Value> x5c = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        ECKey key = new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
                .d(ExampleKeyP256.D)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        // Copy
        key = new ECKey.Builder(key).build();

        // Test getters
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertChain()).isNull();
        Assertions.assertThat(key.getParsedX509CertChain()).isNull();
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testP256ExportAndImport() {

        // Public + private

        ECKey key = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).d(ExampleKeyP256.D).build();

        // Export
        KeyPair pair = key.toKeyPair();

        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        Assertions.assertThat(pub.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
        Assertions.assertThat(pub.getW().getAffineX()).isEqualTo(ExampleKeyP256.X.decodeToBigInteger());
        Assertions.assertThat(pub.getW().getAffineY()).isEqualTo(ExampleKeyP256.Y.decodeToBigInteger());

        ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();
        Assertions.assertThat(priv.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
        Assertions.assertThat(priv.getS()).isEqualTo(ExampleKeyP256.D.decodeToBigInteger());

        // Import
        key = new ECKey.Builder(Curve.P_256, pub).privateKey(priv).build();
        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256.Y);
        Assertions.assertThat(key.getD()).isEqualTo(ExampleKeyP256.D);
        Assertions.assertThat(ExampleKeyP256.D.decode().length).isEqualTo(32);

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testP256AltExportAndImport() {

        ECKey key = new ECKey.Builder(ExampleKeyP256Alt.CRV, ExampleKeyP256Alt.X, ExampleKeyP256Alt.Y).build();

        // Export
        KeyPair pair = key.toKeyPair();

        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        Assertions.assertThat(pub.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
        Assertions.assertThat(pub.getW().getAffineX()).isEqualTo(ExampleKeyP256Alt.X.decodeToBigInteger());
        Assertions.assertThat(pub.getW().getAffineY()).isEqualTo(ExampleKeyP256Alt.Y.decodeToBigInteger());

        // Import
        key = new ECKey.Builder(ExampleKeyP256Alt.CRV, pub).build();
        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP256Alt.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP256Alt.Y);

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testP384AltExportAndImport() {

        ECKey key = new ECKey.Builder(ExampleKeyP384Alt.CRV, ExampleKeyP384Alt.X, ExampleKeyP384Alt.Y).build();

        // Export
        KeyPair pair = key.toKeyPair();

        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        Assertions.assertThat(pub.getParams().getCurve().getField().getFieldSize()).isEqualTo(384);
        Assertions.assertThat(pub.getW().getAffineX()).isEqualTo(ExampleKeyP384Alt.X.decodeToBigInteger());
        Assertions.assertThat(pub.getW().getAffineY()).isEqualTo(ExampleKeyP384Alt.Y.decodeToBigInteger());

        // Import
        key = new ECKey.Builder(ExampleKeyP384Alt.CRV, pub).build();
        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_384);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP384Alt.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP384Alt.Y);

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testP521AltExportAndImport() {

        ECKey key = new ECKey.Builder(ExampleKeyP521Alt.CRV, ExampleKeyP521Alt.X, ExampleKeyP521Alt.Y).build();

        // Export
        KeyPair pair = key.toKeyPair();

        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        Assertions.assertThat(pub.getParams().getCurve().getField().getFieldSize()).isEqualTo(521);
        Assertions.assertThat(pub.getW().getAffineX()).isEqualTo(ExampleKeyP521Alt.X.decodeToBigInteger());
        Assertions.assertThat(pub.getW().getAffineY()).isEqualTo(ExampleKeyP521Alt.Y.decodeToBigInteger());

        // Import
        key = new ECKey.Builder(ExampleKeyP521Alt.CRV, pub).build();
        Assertions.assertThat(key.getCurve()).isEqualTo(Curve.P_521);
        Assertions.assertThat(key.getX()).isEqualTo(ExampleKeyP521Alt.X);
        Assertions.assertThat(key.getY()).isEqualTo(ExampleKeyP521Alt.Y);

        Assertions.assertThat(key.isPrivate()).isFalse();
    }

    @Test
    public void testKeyUseConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        JWK jwk = new ECKey(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y, use, ops, null, null, null, null, null, null);
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(use);
        Assertions.assertThat(jwk.getKeyOperations()).isEqualTo(ops);

        jwk = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
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
            new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
                    .keyUse(use)
                    .keyOperations(ops)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The key use \"use\" and key options \"key_opts\" parameters are not consistent, see RFC 7517, section 4.3");
        }
    }

    @Test
    public void testCookbookExampleKey()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7520#section-3.2

        String json = "{" +
                "\"kty\":\"EC\"," +
                "\"kid\":\"bilbo.baggins@hobbiton.example\"," +
                "\"use\":\"sig\"," +
                "\"crv\":\"P-521\"," +
                "\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
                "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\"," +
                "\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
                "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\"," +
                "\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
                "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\"" +
                "}";

        ECKey jwk = ECKey.parse(json);

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("bilbo.baggins@hobbiton.example");
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(jwk.getCurve()).isEqualTo(Curve.P_521);

        Assertions.assertThat(jwk.getX().toString()).isEqualTo("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
                "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt");

        Assertions.assertThat(jwk.getY().toString()).isEqualTo("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
                "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1");

        Assertions.assertThat(jwk.getD().toString()).isEqualTo("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
                "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt");

        // Convert to Java EC key object
        ECPublicKey ecPublicKey = jwk.toECPublicKey();
        ECPrivateKey ecPrivateKey = jwk.toECPrivateKey();

        jwk = new ECKey.Builder(Curve.P_521, ecPublicKey).privateKey(ecPrivateKey).build();

        Assertions.assertThat(jwk.getX().toString()).isEqualTo("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
                "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt");

        Assertions.assertThat(jwk.getY().toString()).isEqualTo("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
                "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1");

        Assertions.assertThat(jwk.getD().toString()).isEqualTo("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
                "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt");
    }

    @Test
    public void testThumbprint()
            throws Exception {

        ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build();

        Base64URLValue thumbprint = ecKey.computeThumbprint();

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(256 / 8);

        String orderedJSON = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";

        Base64URLValue expected = Base64URLValue.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertThat(thumbprint).isEqualTo(expected);
    }

    @Test
    public void testThumbprintSHA1() {

        ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y).build();

        Base64URLValue thumbprint = ecKey.computeThumbprint("SHA-1");

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(160 / 8);
    }

    @Test
    public void testThumbprintAsKeyID()
            throws Exception {

        ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
                .keyIDFromThumbprint()
                .build();

        Base64URLValue thumbprint = new Base64URLValue(ecKey.getKeyID());

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(256 / 8);

        JsonObjectBuilder builder = Json.createObjectBuilder();
        ecKey.getRequiredParams().forEach(builder::add);
        JsonObject jsonObject = builder.build();
        String orderedJSON = jsonObject.toString();

        Base64URLValue expected = Base64URLValue.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertThat(thumbprint).isEqualTo(expected);
    }

    @Test
    public void testThumbprintSHA1AsKeyID() {

        ECKey ecKey = new ECKey.Builder(ExampleKeyP256.CRV, ExampleKeyP256.X, ExampleKeyP256.Y)
                .keyIDFromThumbprint("SHA-1")
                .build();

        Base64URLValue thumbprint = new Base64URLValue(ecKey.getKeyID());

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(160 / 8);
    }

    @Test
    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    public void testJose4jVectorP256()
            throws Exception {

        String json = "{\"kty\":\"EC\"," +
                "\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
                "\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
                "\"crv\":\"P-256\"}";

        ECKey ecKey = ECKey.parse(json);

        Assertions.assertThat(ecKey.computeThumbprint().toString()).isEqualTo("j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs");
    }

    @Test
    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    public void testJose4jVectorP384()
            throws Exception {

        String json = "{\"kty\":\"EC\"," +
                " \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\"," +
                " \"y\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\"," +
                " \"crv\":\"P-384\"}";

        ECKey ecKey = ECKey.parse(json);

        Assertions.assertThat(ecKey.computeThumbprint().toString()).isEqualTo("vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM");
    }

    @Test
    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    public void testJose4jVectorP521()
            throws Exception {

        String json = "{\"kty\":\"EC\"," +
                "\"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId88hTyHgq180JDt\"," +
                "\"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS42trhDTu\"," +
                "\"crv\":\"P-521\"}";

        ECKey ecKey = ECKey.parse(json);

        Assertions.assertThat(ecKey.computeThumbprint().toString()).isEqualTo("rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg");
    }

    @Test
    // For private EC keys as PKCS#11 handle
    public void testPrivateKeyHandle()
            throws Exception {

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_256.toECParameterSpec());
        KeyPair kp = gen.generateKeyPair();

        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
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

        ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID("1")
                .build();

        Assertions.assertThat(ecJWK.toPublicKey()).isNotNull();
        Assertions.assertThat(ecJWK.toPrivateKey()).isEqualTo(privateKey);
        Assertions.assertThat(ecJWK.isPrivate()).isTrue();

        KeyPair kpOut = ecJWK.toKeyPair();
        Assertions.assertThat(kpOut.getPublic()).isNotNull();
        Assertions.assertThat(kpOut.getPrivate()).isEqualTo(privateKey);

        JsonObject json = ecJWK.toJSONObject().build();
        Assertions.assertThat(json.getString(JWKIdentifiers.KEY_TYPE)).isEqualTo("EC");
        Assertions.assertThat(json.getString("kid")).isEqualTo("1");
        Assertions.assertThat(json.getString("crv")).isEqualTo("P-256");
        Assertions.assertThat(json.get("x")).isNotNull();
        Assertions.assertThat(json.get("y")).isNotNull();
        Assertions.assertThat(json.size()).isEqualTo(5);
    }

    @Test
    public void testX509CertificateChain()
            throws Exception {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_EC);

        ECPublicKey ecPublicKey = (ECPublicKey) chain.get(0).getPublicKey();

        ECKey jwk = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
                .build();

        Assertions.assertThat(jwk.getX509CertChain().get(0)).isEqualTo(SampleCertificates.SAMPLE_X5C_EC.get(0));

        String json = jwk.toJSONString();

        jwk = ECKey.parse(json);

        Assertions.assertThat(jwk.getX509CertChain().get(0)).isEqualTo(SampleCertificates.SAMPLE_X5C_EC.get(0));
    }

    @Test
    public void testX509CertificateChain_algDoesntMatch() {
        try {
            new ECKey.Builder(
                    ExampleKeyP256.CRV,
                    ExampleKeyP256.X,
                    ExampleKeyP256.Y
            )
                    .x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
                    .build();
        } catch (IllegalStateException e) {
            Assertions.assertThat(e.getMessage()).isEqualTo("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
        }
    }

    @Test
    public void testX509CertificateChain_xAndYdontMatch() {

        Assertions.assertThatThrownBy(() -> new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
                        .x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
                        .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
    }

    @Test
    public void testParseFromX509Cert()
            throws Exception {

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();
        ECKey ecKey = ECKey.parse(cert);

        Assertions.assertThat(ecKey.getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(ecKey.getKeyUse()).isNull();
        Assertions.assertThat(ecKey.getKeyID()).isEqualTo(cert.getSerialNumber().toString(10));
        Assertions.assertThat(ecKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(ecKey.getX509CertSHA256Thumbprint()).isEqualTo(Base64URLValue.encode(sha256.digest(cert.getEncoded())));
        Assertions.assertThat(ecKey.getAlgorithm()).isNull();
        Assertions.assertThat(ecKey.getKeyOperations()).isNull();
    }

    @Test
    public void testParseFromX509CertWithRSAPublicKey() {

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
        Assertions.assertThat(cert).isNotNull();

        Assertions.assertThatThrownBy(() -> ECKey.parse(cert))
                .isInstanceOf(JOSEException.class)
                .hasMessage("The public key of the X.509 certificate is not EC");
    }

    @Test
    public void testLoadFromKeyStore()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        // Generate key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_521.toECParameterSpec());
        KeyPair kp = gen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

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
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
        X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());

        // Store
        keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new java.security.cert.Certificate[]{cert});

        // Load
        ECKey ecKey = ECKey.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(ecKey).isNotNull();
        Assertions.assertThat(ecKey.getCurve()).isEqualTo(Curve.P_521);
        Assertions.assertThat(ecKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(ecKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(ecKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(ecKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(ecKey.isPrivate()).isTrue();
        Assertions.assertThat(ecKey.getKeyStore()).isEqualTo(keyStore);

        // Try to load with bad pin
        Assertions.assertThatThrownBy(() -> ECKey.load(keyStore, "1", "".toCharArray()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't retrieve private EC key (bad pin?): Cannot recover key");

    }

    @Test
    public void testLoadFromKeyStore_publicKeyOnly()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/wikipedia.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);

        keyStore.setCertificateEntry("1", cert);

        ECKey ecKey = ECKey.load(keyStore, "1", null);
        Assertions.assertThat(ecKey).isNotNull();
        Assertions.assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
        Assertions.assertThat(ecKey.getKeyUse()).isNull();
        Assertions.assertThat(ecKey.getKeyID()).isEqualTo("1");
        Assertions.assertThat(ecKey.getX509CertChain().size()).isEqualTo(1);
        Assertions.assertThat(ecKey.getX509CertSHA256Thumbprint()).isNotNull();
        Assertions.assertThat(ecKey.isPrivate()).isFalse();
        Assertions.assertThat(ecKey.getKeyStore()).isEqualTo(keyStore);
    }

    @Test
    public void testLoadFromKeyStore_notEC()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        String pemEncodedCert = IOUtil.readFileToString("src/test/resources/sample-certs/ietf.crt");
        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);

        keyStore.setCertificateEntry("1", cert);

        Assertions.assertThatThrownBy(() -> ECKey.load(keyStore, "1", null))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't load EC JWK: The key algorithm is not EC");
    }

    @Test
    public void testLoadFromKeyStore_notFound()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        Assertions.assertThat(ECKey.load(keyStore, "1", null)).isNull();
    }

    @Test
    // iss #217
    public void testEnsurePublicXYCoordinatesOnCurve_1() {

        Assertions.assertThatThrownBy(
                        () -> new ECKey(
                                Curve.P_256,
                                ExampleKeyP384Alt.X, // on diff curve
                                ExampleKeyP384Alt.Y, // on diff curve
                                KeyUse.SIGNATURE,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve");
    }

    @Test
    // iss #217
    public void testEnsurePublicXYCoordinatesOnCurve_2() {

        Assertions.assertThatThrownBy(
                        () -> new ECKey(
                                Curve.P_256,
                                ExampleKeyP384Alt.X, // on diff curve
                                ExampleKeyP384Alt.Y, // on diff curve
                                ExampleKeyP256.D,    // private D coordinate
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve");
    }

    @Test
    public void ECKeyBuilder_correctCurve_1()
            throws Exception {

        // EC key on P_256
        ECParameterSpec ecParameterSpec = Curve.P_256.toECParameterSpec();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();
        Assertions.assertThatCode(
                () -> new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                        .privateKey((ECPrivateKey) keyPair.getPrivate())
                        .build()
        ).doesNotThrowAnyException();

    }

    @Test
    public void ECKeyBuilder_correctCurve_2()
            throws Exception {

        // EC key on P_384
        ECParameterSpec ecParameterSpec = Curve.P_384.toECParameterSpec();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();
        Assertions.assertThatCode(
                () -> new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .build()
        ).doesNotThrowAnyException();

    }

    @Test
    // iss #217
    public void testCurveMismatch()
            throws Exception {

        // EC key on P_384
        ECParameterSpec ecParameterSpec = Curve.P_384.toECParameterSpec();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();
        ECKey ecJWK_p384 = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .build();

        // Try to create EC key with P_256 params, but with x and y from P_384 curve key

        ECPoint w = new ECPoint(ecJWK_p384.getX().decodeToBigInteger(), ecJWK_p384.getY().decodeToBigInteger());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, Curve.P_256.toECParameterSpec());

        // Default Sun provider
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        Assertions.assertThatThrownBy(() -> keyFactory.generatePublic(publicKeySpec))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Point coordinates do not match field size");

        // BouncyCastle provider
        KeyFactory keyFactory2 = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        Assertions.assertThatThrownBy(
                        () -> keyFactory2.generatePublic(publicKeySpec))
                .isInstanceOf(Exception.class)
                .hasMessage("invalid KeySpec: x value invalid for SecP256R1FieldElement");
    }

    @Test
    public void testEqualsSuccess()
            throws Exception {

        //Given
        String jsonA = "{\n" +
                "    \"kty\" : \"EC\",\n" +
                "    \"crv\" : \"P-256\",\n" +
                "    \"x\"   : \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "    \"y\"   : \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "    \"use\" : \"enc\",\n" +
                "    \"kid\" : \"1\"\n" +
                "  }";
        ECKey ecKeyA = ECKey.parse(jsonA.replaceAll("\n", ""));
        ECKey ecKeyB = ECKey.parse(jsonA.replaceAll("\n", ""));

        //When

        //Then
        Assertions.assertThat(ecKeyB).isEqualTo(ecKeyA);
    }

    @Test
    public void testEqualsFailure()
            throws Exception {

        //Given
        String jsonA = "{\n" +
                "    \"kty\" : \"EC\",\n" +
                "    \"crv\" : \"P-256\",\n" +
                "    \"x\"   : \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "    \"y\"   : \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "    \"use\" : \"enc\",\n" +
                "    \"kid\" : \"1\"\n" +
                "  }";
        ECKey ecKeyA = ECKey.parse(jsonA.replaceAll("\n", ""));

        String jsonB = "{\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"d\": \"l3zQlaKsoql3cBEQzVpFnWIyHyGRh_C3cc0l3iqnljE\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"x\": \"LE9B4rxnp-1kzJsDBM-UYTsewGooMgt1Pi_czT_E7SI\",\n" +
                "      \"y\": \"fs_LRmTZVHRUZintk-BLOpIjOjxTmVXF9ddrwNuRH9U\",\n" +
                "      \"use\" : \"enc\",\n" +
                "      \"kid\" : \"1\"\n" +
                "    }";
        ECKey ecKeyB = ECKey.parse(jsonB.replaceAll("\n", ""));

        //When

        //Then
        Assertions.assertThat(ecKeyA).isNotEqualTo(ecKeyB);
    }


    @Test
    public void testBuilderWithAtbashKey() {
        List<AtbashKey> keys = TestKeys.generateECKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        ECKey ecKey = new ECKey.Builder(Curve.P_256, publicKey.get(0)).build();
        Assertions.assertThat(ecKey).isNotNull();
    }

    @Test
    public void testBuilderWithAtbashKey_WrongType() {
        List<AtbashKey> keys = TestKeys.generateECKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        Assertions.assertThatThrownBy(
                        () -> new ECKey.Builder(Curve.P_256, publicKey.get(0)).build())
                .isInstanceOf(KeyTypeException.class)
                .hasMessage("PUBLIC key required for ECKey creation");

    }

    @Test
    public void testBuilderWithAtbashKey_WrongKey() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        Assertions.assertThatThrownBy(() -> new ECKey.Builder(Curve.P_256, publicKey.get(0)).build())
                .isInstanceOf(KeyTypeException.class)
                .hasMessage("Unsupported KeyType RSA for ECKey creation");

    }

    @Test
    public void testParse_fromEmptyJSONObject() {

        JsonObject jsonObject = Json.createObjectBuilder().build();
        Assertions.assertThatThrownBy(() -> ECKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key type to parse must not be null");

    }


    @Test
    public void testParse_missingCurve() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "EC")
                .add(JWKIdentifiers.X_COORD, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
                .add(JWKIdentifiers.Y_COORD, "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
                .build();
        Assertions.assertThatThrownBy(() -> ECKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The cryptographic curve string must not be null or empty");

    }

    @Test
    public void testParse_missingX() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "EC")
                .add(JWKIdentifiers.CURVE, "P-256")
                .add(JWKIdentifiers.Y_COORD, "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
                .build();
        Assertions.assertThatThrownBy(() -> ECKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The 'x' coordinate must not be null");

    }


    @Test
    public void testParse_missingY() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "EC")
                .add(JWKIdentifiers.CURVE, "P-256")
                .add(JWKIdentifiers.X_COORD, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
                .build();
        Assertions.assertThatThrownBy(() -> ECKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The 'y' coordinate must not be null");

    }
}