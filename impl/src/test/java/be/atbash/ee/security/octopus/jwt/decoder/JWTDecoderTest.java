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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.MyColor;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.TestKeySelector;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.proc.BadJOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.CommonJWTHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimNames;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.InvalidBase64ValueException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import javax.json.Json;
import javax.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.*;

class JWTDecoderTest {

    private final JWTDecoder decoder = new JWTDecoder();

    @AfterEach
    public void cleanup() {
        MDC.clear();
    }

    @Test
    void decode() {

        String data = "{\"pets\":\"dog,cat\",\"dateValue\":\"2017-11-15\",\"valueForClass\":\"Atbash\"}";

        Map<String, String> result = decoder.decode(data, HashMap.class).getData();


        Assertions.assertThat(result.keySet()).containsOnlyOnce("pets", "dateValue", "valueForClass");
    }

    @Test
    void decode_customSerializer() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        JWTParameters parameters = getJwtParameters(keys, null);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "200,150,100").build();

        ListKeyManager keyManager = new ListKeyManager(keys);

        String json = encoder.encode(claims, parameters);

        JWTData<MyColor> myColor = decoder.decode(json, MyColor.class, new TestKeySelector(keyManager));
        Assertions.assertThat(myColor).isNotNull();
        MyColor data = myColor.getData();
        Assertions.assertThat(data).isNotNull();
        Assertions.assertThat(data.getR()).isEqualTo(200);
        Assertions.assertThat(data.getG()).isEqualTo(150);
        Assertions.assertThat(data.getB()).isEqualTo(100);

    }

    @Test
    void decode_plainJWT() {
        String json = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.";
        JWTData<Map> jwtData = decoder.decode(json, Map.class);

        Assertions.assertThat(jwtData).isNotNull();
        Map map = jwtData.getData();
        Assertions.assertThat(map).hasSize(1);
        Assertions.assertThat(map).containsEntry("sub", "alice");
    }

    @Test
    void decode_plainJWT_json() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("protected", "eyJhbGciOiJub25lIn0")
                .add("payload", "eyJzdWIiOiJhbGljZSJ9")
                .build();

        JWTData<Map> jwtData = decoder.decode(jsonObject, Map.class);

        Assertions.assertThat(jwtData).isNotNull();
        Map map = jwtData.getData();
        Assertions.assertThat(map).hasSize(1);
        Assertions.assertThat(map).containsEntry("sub", "alice");
    }

    @Test
    void decode_plainJWT_omittedDot() {
        String json = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9";  // Explicitly omitted the end . (But not recommended !)
        JWTData<Map> jwtData = decoder.decode(json, Map.class);

        Assertions.assertThat(jwtData).isNotNull();
        Map map = jwtData.getData();
        Assertions.assertThat(map).hasSize(1);
        Assertions.assertThat(map).containsEntry("sub", "alice");
    }

    @Test
    void decode_plainJWT_ClaimSet() {
        String json = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vYXRiYXNoLmJlIiwiYXVkIjoic29tZUNsaWVudCIsInN1YiI6InRoZVN1YmplY3QiLCJleHAiOjE1NzkzNTgxODN9.";
        JWTData<JWTClaimsSet> jwtData = decoder.decode(json, JWTClaimsSet.class);
        Assertions.assertThat(jwtData).isNotNull();
        JWTClaimsSet jwtClaimsSet = jwtData.getData();

        Map<String, Object> claims = jwtClaimsSet.getClaims();
        Assertions.assertThat(claims).hasSize(4);
        Assertions.assertThat(claims).containsKeys("aud", "sub", "iss", "exp");

    }

    @Test
    void decode_plainJWT_ClaimSet_json() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("protected", "eyJhbGciOiJub25lIn0")
                .add("payload", "eyJpc3MiOiJodHRwOi8vYXRiYXNoLmJlIiwiYXVkIjoic29tZUNsaWVudCIsInN1YiI6InRoZVN1YmplY3QiLCJleHAiOjE1NzkzNTgxODN9")
                .build();

        JWTData<JWTClaimsSet> jwtData = decoder.decode(jsonObject, JWTClaimsSet.class);

        Assertions.assertThat(jwtData).isNotNull();
        JWTClaimsSet jwtClaimsSet = jwtData.getData();

        Map<String, Object> claims = jwtClaimsSet.getClaims();
        Assertions.assertThat(claims).hasSize(4);
        Assertions.assertThat(claims).containsKeys("aud", "sub", "iss", "exp");

    }

    @Test
    void decode_withVerifier_valid() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value1");
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();


        String json = encoder.encode(claims, parameters);

        JWTVerifier verifier = (header, jwtClaimsSet) -> {
            boolean result = true;
            if (!"value1".equals(header.getCustomParameter("head1"))) {
                result = false;
            }
            if (!"123".equals(jwtClaimsSet.getClaim("value"))) {
                result = false;
            }


            return result;
        };

        ListKeyManager keyManager = new ListKeyManager(keys);
        Map<String, String> result = decoder.decode(json, HashMap.class, new TestKeySelector(keyManager), verifier).getData();

        Assertions.assertThat(result.keySet()).containsOnlyOnce("value");
    }

    @Test
    void decode_withVerifier_valid_json() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value1");
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();


        String json = encoder.encode(claims, parameters);
        String[] parts = json.split("\\.");
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("protected", parts[0])
                .add("payload", parts[1])
                .add("signature", parts[2])
                .build();

        JWTVerifier verifier = (header, jwtClaimsSet) -> {
            boolean result = true;
            if (!"value1".equals(header.getCustomParameter("head1"))) {
                result = false;
            }
            if (!"123".equals(jwtClaimsSet.getClaim("value"))) {
                result = false;
            }


            return result;
        };

        ListKeyManager keyManager = new ListKeyManager(keys);
        Map<String, String> result = decoder.decode(jsonObject, HashMap.class, new TestKeySelector(keyManager), verifier).getData();

        Assertions.assertThat(result.keySet()).containsOnlyOnce("value");
    }

    @Test
    void decode_withVerifier_invalidHeader() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value2");
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();


        String json = encoder.encode(claims, parameters);

        JWTVerifier verifier = (header, jwtClaimsSet) -> {
            boolean result = true;
            if (!"value1".equals(header.getCustomParameter("head1"))) {
                result = false;
            }
            if (!"123".equals(jwtClaimsSet.getClaim("value"))) {
                result = false;
            }


            return result;
        };

        ListKeyManager keyManager = new ListKeyManager(keys);
        Assertions.assertThatThrownBy(() -> decoder.decode(json, HashMap.class, new TestKeySelector(keyManager), verifier))
                .isInstanceOf(InvalidJWTException.class)
                .hasMessage("JWT verification failed");
    }


    @Test
    void decode_withVerifier_invalidClaim() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value2");
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();

        String json = encoder.encode(claims, parameters);

        JWTVerifier verifier = (header, jwtClaimsSet) -> {
            boolean result = true;
            if (!"value1".equals(header.getCustomParameter("head1"))) {
                result = false;
            }
            if (!"321".equals(jwtClaimsSet.getClaim("value"))) {
                result = false;
            }


            return result;
        };

        ListKeyManager keyManager = new ListKeyManager(keys);

        Assertions.assertThatThrownBy(() -> decoder.decode(json, HashMap.class, new TestKeySelector(keyManager), verifier))
                .isInstanceOf(InvalidJWTException.class)
                .hasMessage("JWT verification failed");

    }

    @Test
    void decode_customSerializer_withVerifier() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        JWTParameters parameters = getJwtParameters(keys, null);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "200,150,100").build();

        ListKeyManager keyManager = new ListKeyManager(keys);

        String json = encoder.encode(claims, parameters);

        JWTVerifier verifier = (header, jwtClaimsSet) -> {
            boolean result = true;
            // Important for documentation, verifier uses the raw claims format (Converter not yet kicked in)
            if (!"200,150,100".equals(jwtClaimsSet.getClaim("value"))) {
                result = false;
            }


            return result;
        };
        JWTData<MyColor> myColor = decoder.decode(json, MyColor.class, new TestKeySelector(keyManager), verifier);
        Assertions.assertThat(myColor).isNotNull();
        MyColor data = myColor.getData();
        Assertions.assertThat(data).isNotNull();
        Assertions.assertThat(data.getR()).isEqualTo(200);
        Assertions.assertThat(data.getG()).isEqualTo(150);
        Assertions.assertThat(data.getB()).isEqualTo(100);

    }

    @Test
    void decode_withCritHeader() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value1");
        Set<String> critValues = new HashSet<>();
        critValues.add("someHeaderClaim");
        headerValues.put("crit", critValues);
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();

        String json = encoder.encode(claims, parameters);

        ListKeyManager keyManager = new ListKeyManager(keys);
        Map<String, String> result = decoder.decode(json, HashMap.class, new TestKeySelector(keyManager), "someHeaderClaim").getData();
        Assertions.assertThat(result.keySet()).containsOnlyOnce("value");
    }

    @Test
    void decode_withCritHeader_Missing() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value1");
        Set<String> critValues = new HashSet<>();
        critValues.add("someHeaderClaim");
        headerValues.put("crit", critValues);
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();

        String json = encoder.encode(claims, parameters);

        ListKeyManager keyManager = new ListKeyManager(keys);

        Assertions.assertThatThrownBy(
                        () -> decoder.decode(json, HashMap.class, new TestKeySelector(keyManager))
                ).isInstanceOf(InvalidJWTException.class)
                .hasMessage("Signed JWT rejected: Invalid signature");
        Assertions.assertThat(MDC.getCopyOfContextMap().get("jwt.verification.fail")).isEqualTo("Verification failed due to 'crit' header parameter deferral policy");
    }

    @Test
    void decode_withCritHeader_withVerifier() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        Map<String, Object> headerValues = new HashMap<>();
        headerValues.put("head1", "value1");
        Set<String> critValues = new HashSet<>();
        critValues.add("someHeaderClaim");
        headerValues.put("crit", critValues);
        JWTParameters parameters = getJwtParameters(keys, headerValues);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "123").build();

        String json = encoder.encode(claims, parameters);

        ListKeyManager keyManager = new ListKeyManager(keys);
        JWTVerifier verifier = new JWTVerifier() {
            @Override
            public boolean verify(CommonJWTHeader header, JWTClaimsSet jwtClaimsSet) {
                return true;
            }

            @Override
            public Set<String> getSupportedCritHeaderValues() {
                Set<String> result = new HashSet<>();
                result.add("someHeaderClaim");

                return result;
            }
        };
        Map<String, String> result = decoder.decode(json, HashMap.class, new TestKeySelector(keyManager), verifier).getData();
        Assertions.assertThat(result.keySet()).containsOnlyOnce("value");
    }

    private JWTParameters getJwtParameters(List<AtbashKey> keys, Map<String, Object> headerValues) {

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keyList.get(0));

        if (headerValues != null) {
            headerValues.forEach(builder::withHeaderObject);
        }
        return builder.build();
    }

    @Test
    void determineEncoding_JSON() {
        JWTEncoding jwtEncoding = decoder.determineEncoding("{\"name\":\"John Doe\",\"age\":42}");
        Assertions.assertThat(jwtEncoding).isEqualTo(JWTEncoding.NONE);
    }

    @Test
    void determineEncoding_String() {
        JWTEncoding jwtEncoding = decoder.determineEncoding("Just a plain String");
        Assertions.assertThat(jwtEncoding).isNull();
    }

    @Test
    void determineEncoding_PlainJWT() {
        String json = "{\"name\":\"John Doe\",\"age\":42}";
        String data = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        JWTEncoding jwtEncoding = decoder.determineEncoding(data + ".");
        Assertions.assertThat(jwtEncoding).isEqualTo(JWTEncoding.PLAIN);
    }

    @Test
    void determineEncoding_signedJWT() {
        String json = "{\"name\":\"John Doe\",\"age\":42}";
        String data = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        JWTEncoding jwtEncoding = decoder.determineEncoding(data + ".payload.signature");
        Assertions.assertThat(jwtEncoding).isEqualTo(JWTEncoding.JWS);
    }

    @Test
    void determineEncoding_encryptedJWT() {
        String json = "{\"name\":\"John Doe\",\"age\":42}";
        String data = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        JWTEncoding jwtEncoding = decoder.determineEncoding(data + ".encryptedKey.initializationVector.cipherText.authenticationTag");
        Assertions.assertThat(jwtEncoding).isEqualTo(JWTEncoding.JWE);
    }

    @Test
    void decode_NoEncoding() {
        Assertions.assertThatThrownBy(() -> decoder.decode("Just a plain String", JWTClaimsSet.class, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unable to determine the encoding of the data");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("Unable to determine the encoding of the provided token");
    }

    @Test
    void decode_unencodedPayload_failsBase64Decode() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid", 2048);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);

        Assertions.assertThat(privateKeys).hasSize(1);
        JWSSigner signer = new RSASSASigner(privateKeys.get(0));

        Map<String, Object> criticalParameters = new HashMap<>();
        criticalParameters.put(JWTClaimNames.ISSUER, "https://issuer.example.com");
        criticalParameters.put(JWTClaimNames.ISSUED_AT, DateUtils.toSecondsSinceEpoch(new Date()));

        Payload payload = new Payload("{\"key\":\"value\"}");

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .base64URLEncodePayload(false)
                        .keyID("kid")
                        .criticalParams(criticalParameters.keySet())
                        .parameters(criticalParameters)
                        .build(),
                payload);

        jwsObject.sign(signer);

        String data = jwsObject.serialize(false);

        ListKeyManager keyManager = new ListKeyManager(keys);

        Assertions.assertThatThrownBy(() -> decoder.decode(data, JWTClaimsSet.class, new TestKeySelector(keyManager)))
                .isInstanceOf(InvalidBase64ValueException.class);

    }

    @Test
    void decode_unencodedPayload() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid", 2048);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);

        Assertions.assertThat(privateKeys).hasSize(1);
        JWSSigner signer = new RSASSASigner(privateKeys.get(0));

        Map<String, Object> criticalParameters = new HashMap<>();
        criticalParameters.put(JWTClaimNames.ISSUER, "https://issuer.example.com");
        criticalParameters.put(JWTClaimNames.ISSUED_AT, DateUtils.toSecondsSinceEpoch(new Date()));

        Payload payload = new Payload("test1234");

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .base64URLEncodePayload(false)
                        .keyID("kid")
                        .criticalParams(criticalParameters.keySet())
                        .parameters(criticalParameters)
                        .build(),
                payload);

        jwsObject.sign(signer);

        String data = jwsObject.serialize(false);

        ListKeyManager keyManager = new ListKeyManager(keys);

        Assertions.assertThatThrownBy(() -> decoder.decode(data, JWTClaimsSet.class, new TestKeySelector(keyManager)))
                .isInstanceOf(BadJOSEException.class)
                .hasMessage("Unencoded payload not allowed");

    }
}