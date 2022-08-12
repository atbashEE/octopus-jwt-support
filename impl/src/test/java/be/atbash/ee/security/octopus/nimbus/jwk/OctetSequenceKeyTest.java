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
import be.atbash.ee.security.octopus.nimbus.SampleCertificates;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;


/**
 * Tests the Octet Sequence JWK class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class OctetSequenceKeyTest {


    @Test
    public void testConstructorAndSerialization()
            throws Exception {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");
        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetSequenceKey key = new OctetSequenceKey(k, null, ops, JWSAlgorithm.HS256, "1", x5u, x5t256, x5c, keyStore);

        Assertions.assertThat(key).isInstanceOf(SecretJWK.class);

        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        byte[] keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {
            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);
        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();

        String jwkString = key.toJSONObject().build().toString();

        key = OctetSequenceKey.parse(jwkString);

        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {

            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);

        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testAltConstructorAndSerialization()
            throws Exception {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");
        URI x5u = new URI("http://example.com/jwk.json");
        Base64URLValue x5t256 = new Base64URLValue("abc256");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        OctetSequenceKey key = new OctetSequenceKey(k, KeyUse.SIGNATURE, null, JWSAlgorithm.HS256, "1", x5u, x5t256, x5c, null);

        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        byte[] keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {
            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);
        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();

        String jwkString = key.toJSONObject().build().toString();

        key = OctetSequenceKey.parse(jwkString);

        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        Assertions.assertThat(key.getKeyOperations()).isNull();
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertSHA256Thumbprint().toString()).isEqualTo(x5t256.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {

            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);

        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testKeyUseConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        JWK jwk = new OctetSequenceKey(new Base64URLValue("GawgguFyGrWKav7AX4VKUg"), use, ops, null, null, null, null, null, null);
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(use);
        Assertions.assertThat(jwk.getKeyOperations()).isEqualTo(ops);
    }

    @Test
    public void testRejectKeyUseNotConsistentWithOps() {

        Assertions.assertThatThrownBy(
                        () -> new OctetSequenceKey.Builder(new Base64URLValue("GawgguFyGrWKav7AX4VKUg"))
                                .keyUse(KeyUse.SIGNATURE)
                                .keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
                                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("The key use \"use\" and key options \"key_opts\" parameters are not consistent, see RFC 7517, section 4.3");
    }

    @Test
    public void testBuilder()
            throws Exception {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");
        URI x5u = new URI("http://example.com/jwk.json");
        List<Base64Value> x5c = SampleCertificates.SAMPLE_X5C_RSA;

        Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        OctetSequenceKey key = new OctetSequenceKey.Builder(k)
                .keyOperations(ops)
                .algorithm(JWSAlgorithm.HS256)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertChain(x5c)
                .keyStore(keyStore)
                .build();

        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isEqualTo(keyStore);

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        byte[] keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {
            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);
        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();


        String jwkString = key.toJSONObject().build().toString();

        key = OctetSequenceKey.parse(jwkString);


        Assertions.assertThat(key.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(key.getKeyUse()).isNull();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(key.getKeyOperations().contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(key.getKeyOperations().size()).isEqualTo(2);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(key.getKeyID()).isEqualTo("1");
        Assertions.assertThat(key.getX509CertURL().toString()).isEqualTo(x5u.toString());
        Assertions.assertThat(key.getX509CertChain().size()).isEqualTo(x5c.size());
        Assertions.assertThat(key.getKeyStore()).isNull();

        Assertions.assertThat(key.getKeyValue()).isEqualTo(k);

        keyBytes = k.decode();

        for (int i = 0; i < keyBytes.length; i++) {
            Assertions.assertThat(key.toByteArray()[i]).isEqualTo(keyBytes[i]);
        }

        Assertions.assertThat(key.toPublicJWK()).isNull();

        Assertions.assertThat(key.isPrivate()).isTrue();
    }

    @Test
    public void testBuilderWithByteArray() {

        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        OctetSequenceKey oct = new OctetSequenceKey.Builder(key).build();

        Assertions.assertThat(oct.getKeyValue()).isEqualTo(Base64URLValue.encode(key));
    }

    @Test
    public void testBuilderWithSecretKey() {

        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        OctetSequenceKey oct = new OctetSequenceKey.Builder(new SecretKeySpec(key, "MAC")).keyUse(KeyUse.SIGNATURE).build();

        SecretKey secretKey = oct.toSecretKey();
        Assertions.assertThat(Arrays.equals(key, secretKey.getEncoded())).isTrue();
        Assertions.assertThat(secretKey.getAlgorithm()).isEqualTo("AES");  // Since Algorithm isn't preserved in the JWK
    }

    @Test
    public void testCookbookHMACKeyExample()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7c520#section-3.5

        String json = "{" +
                "\"kty\":\"oct\"," +
                "\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\"," +
                "\"use\":\"sig\"," +
                "\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"" +
                "}";

        OctetSequenceKey jwk = OctetSequenceKey.parse(json);

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("018c0ae5-4d9b-471b-bfd6-eef314bc7037");
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);

        Assertions.assertThat(jwk.getKeyValue().toString()).isEqualTo("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg");
    }

    @Test
    public void testCookbookAESKeyExample()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7520#section-5.3.1

        String json = "{" +
                "\"kty\":\"oct\"," +
                "\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\"," +
                "\"use\":\"enc\"," +
                "\"alg\":\"A128GCM\"," +
                "\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\"" +
                "}";

        OctetSequenceKey jwk = OctetSequenceKey.parse(json);

        Assertions.assertThat(jwk.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("77c7e2b8-6e13-45cf-8672-617b5b45243a");
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        Assertions.assertThat(jwk.getAlgorithm()).isEqualTo(EncryptionMethod.A128GCM);

        Assertions.assertThat(jwk.getKeyValue().toString()).isEqualTo("XctOhJAkA-pD9Lh7ZgW_2A");
    }

    @Test
    public void testToSecretKey() {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

        Assertions.assertThat(Arrays.equals(k.decode(), jwk.toSecretKey().getEncoded())).isTrue();
        Assertions.assertThat(jwk.toSecretKey().getAlgorithm()).isEqualTo("AES");
    }

    @Test
    public void testToSecretKeyWithAlg() {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

        Assertions.assertThat(Arrays.equals(k.decode(), jwk.toSecretKey().getEncoded())).isTrue();
        Assertions.assertThat(jwk.toSecretKey().getAlgorithm()).isEqualTo("AES");
    }

    @Test
    public void testThumbprint()
            throws Exception {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

        Base64URLValue thumbprint = jwk.computeThumbprint();

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(256 / 8);

        String orderedJSON = "{\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}";

        Base64URLValue expected = Base64URLValue.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertThat(thumbprint).isEqualTo(expected);
    }

    @Test
    public void testThumbprintSHA1() {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

        Base64URLValue thumbprint = jwk.computeThumbprint("SHA-1");

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(160 / 8);
    }

    @Test
    public void testThumbprintAsKeyID()
            throws Exception {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).keyIDFromThumbprint().build();

        Base64URLValue thumbprint = new Base64URLValue(jwk.getKeyID());

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(256 / 8);

        JsonObjectBuilder builder = Json.createObjectBuilder();
        jwk.getRequiredParams().forEach(builder::add);
        JsonObject jsonObject = builder.build();


        Base64URLValue expected = Base64URLValue.encode(MessageDigest.getInstance("SHA-256").digest(jsonObject.toString().getBytes(StandardCharsets.UTF_8)));

        Assertions.assertThat(thumbprint).isEqualTo(expected);
    }

    @Test
    public void testThumbprintSHA1AsKeyID() {

        Base64URLValue k = new Base64URLValue("GawgguFyGrWKav7AX4VKUg");

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).keyIDFromThumbprint("SHA-1").build();

        Base64URLValue thumbprint = new Base64URLValue(jwk.getKeyID());

        Assertions.assertThat(thumbprint.decode().length).isEqualTo(160 / 8);
    }


    @Test
    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    public void testJose4jVector()
            throws Exception {

        String json = "{\"kty\":\"oct\"," +
                "\"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}";

        OctetSequenceKey jwk = OctetSequenceKey.parse(json);

        Assertions.assertThat(jwk.computeThumbprint().toString()).isEqualTo("7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g");
    }

    @Test
    public void testSize() {

        byte[] keyMaterial = new byte[24];
        new SecureRandom().nextBytes(keyMaterial);
        Assertions.assertThat(new OctetSequenceKey.Builder(keyMaterial).build().size()).isEqualTo(24 * 8);
    }

    @Test
    public void testLoadFromKeyStore()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey secretKey = gen.generateKey();

        keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));

        OctetSequenceKey octJWK = OctetSequenceKey.load(keyStore, "1", "1234".toCharArray());
        Assertions.assertThat(octJWK).isNotNull();
        Assertions.assertThat(octJWK.getKeyID()).isEqualTo("1");
        Assertions.assertThat(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray())).isTrue();
        Assertions.assertThat(octJWK.getKeyStore()).isEqualTo(keyStore);
    }

    @Test
    public void testLoadFromKeyStore_emptyPassword()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey secretKey = gen.generateKey();

        keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("".toCharArray()));

        OctetSequenceKey octJWK = OctetSequenceKey.load(keyStore, "1", "".toCharArray());
        Assertions.assertThat(octJWK).isNotNull();
        Assertions.assertThat(octJWK.getKeyID()).isEqualTo("1");
        Assertions.assertThat(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray())).isTrue();
        Assertions.assertThat(octJWK.getKeyStore()).isEqualTo(keyStore);
    }

    @Test
    public void testLoadFromKeyStore_notFound()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        Assertions.assertThat(OctetSequenceKey.load(keyStore, "1", "1234".toCharArray())).isNull();
    }

    @Test
    public void testLoadFromKeyStore_badPin()
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] password = "secret".toCharArray();
        keyStore.load(null, password);

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey secretKey = gen.generateKey();

        keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));

        Assertions.assertThatThrownBy(
                        () -> OctetSequenceKey.load(keyStore, "1", "badpin".toCharArray()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Couldn't retrieve secret key (bad pin?): Given final block not properly padded. Such issues can arise if a bad key is used during decryption.");
    }

    @Test
    public void testEqualsSuccess()
            throws Exception {

        //Given
        String json = "{" +
                "\"kty\":\"oct\"," +
                "\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\"," +
                "\"use\":\"sig\"," +
                "\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"" +
                "}";

        OctetSequenceKey jwkA = OctetSequenceKey.parse(json);
        OctetSequenceKey jwkB = OctetSequenceKey.parse(json);

        //When

        //Then
        Assertions.assertThat(jwkB).isEqualTo(jwkA);
    }

    @Test
    public void testEqualsFailure()
            throws Exception {

        //Given
        String jsonA = "{" +
                "\"kty\":\"oct\"," +
                "\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\"," +
                "\"use\":\"sig\"," +
                "\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"" +
                "}";
        OctetSequenceKey jwkA = OctetSequenceKey.parse(jsonA);

        String jsonB = "{" +
                "\"kty\":\"oct\"," +
                "\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\"," +
                "\"use\":\"sig\"," +
                "\"k\":\"werewrwerewr\"" +
                "}";
        OctetSequenceKey jwkB = OctetSequenceKey.parse(jsonB);

        //When

        //Then
        Assertions.assertThat(jwkA).isNotEqualTo(jwkB);

    }

    @Test
    public void testBuilderWithAtbashKey() {
        List<AtbashKey> keys = TestKeys.generateOCTKeys("kid");

        OctetSequenceKey key = new OctetSequenceKey.Builder(keys.get(0)).build();
        Assertions.assertThat(key).isNotNull();
    }

    @Test
    public void testBuilderWithAtbashKey_WrongKey() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Assertions.assertThatThrownBy(
                        () -> new OctetSequenceKey.Builder(keys.get(0)).build())
                .isInstanceOf(KeyTypeException.class)
                .hasMessage("Unsupported KeyType RSA for OctetSequenceKey creation");

    }

    @Test
    public void testParse_fromEmptyJSONObject() {

        JsonObject jsonObject = Json.createObjectBuilder().build();

        Assertions.assertThatThrownBy(() -> OctetSequenceKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key type to parse must not be null");

    }

    @Test
    public void testParse_missingKty() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.OCT_KEY_VALUE, "werewrwerewr")
                .build();

        Assertions.assertThatThrownBy(() -> OctetSequenceKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key type to parse must not be null");

    }

    @Test
    public void testParse_missingK() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "oct")
                .build();

        Assertions.assertThatThrownBy(() -> OctetSequenceKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key value must not be null");
    }


    @Test
    public void testParse_nullK() {

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(JWKIdentifiers.KEY_TYPE, "oct")
                .add(JWKIdentifiers.OCT_KEY_VALUE, JsonValue.NULL)
                .build();

        Assertions.assertThatThrownBy(() -> OctetSequenceKey.parse(jsonObject))
                .isInstanceOf(ParseException.class)
                .hasMessage("The key value must not be null");


    }

}