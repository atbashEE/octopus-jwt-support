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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.MyColor;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersPlain;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTEncoderTest {

    private Payload payload;

    @BeforeEach
    public void setup() {
        payload = new Payload();
        payload.setValue("JUnit");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");
    }

    @Test
    public void encodeObject_json() {
        // Encode a POJO to JSON, without wrapping in JWT

        JWTParameters parameters = new JWTParametersNone();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(payload, parameters);

        // Can't use equals checks as order of elements in JSON aren't defined.
        assertThat(json).contains("\"number\":42");
        assertThat(json).contains("\"myList\":[\"permission1\",\"permission2\"]");
        assertThat(json).contains("\"value\":\"JUnit\"");
    }

    @Test
    public void encodeObject_plain() {
        // Encode a POJO to JWT but not signed.

        JWTParameters parameters = new JWTParametersPlain();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(payload, parameters);

        assertThat(json).endsWith(".");
        String[] jwtParts = json.split("\\.");
        assertThat(jwtParts).hasSize(2);

        Map<String, Object> header = getJson(jwtParts[0]);
        assertThat(header).hasSize(1);
        assertThat(header).containsEntry("alg", "none");

        Map<String, Object> content = getJson(jwtParts[1]);
        assertThat(content).hasSize(3);
        assertThat(content).containsEntry("number", BigDecimal.valueOf(42));
        assertThat(content).containsKey("myList");
        List<String> list = (List<String>) content.get("myList");
        assertThat(list).containsOnly("permission1", "permission2");
        assertThat(content).containsEntry("value", "JUnit");

    }

    @Test
    public void encode_JwtClaimSet_plain() {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        Date exp = new Date();
        builder.issuer("http://atbash.be")
                .audience("someClient")
                .subject("theSubject")
                .expirationTime(exp);

        JWTClaimsSet jwtClaimsSet = builder.build();

        JWTParameters parameters = new JWTParametersPlain();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(jwtClaimsSet, parameters);

        assertThat(json).endsWith(".");
        String[] jwtParts = json.split("\\.");
        assertThat(jwtParts).hasSize(2);

        Map<String, Object> header = getJson(jwtParts[0]);
        assertThat(header).hasSize(1);
        assertThat(header).containsEntry("alg", "none");

        Map<String, Object> content = getJson(jwtParts[1]);
        assertThat(content).hasSize(4);
        assertThat(content.keySet()).containsOnly("aud", "sub", "iss", "exp");

        assertThat(content.get("aud")).isEqualTo("someClient");
        assertThat(content.get("sub")).isEqualTo("theSubject");
        assertThat(content.get("iss")).isEqualTo("http://atbash.be");
        assertThat(content.get("exp")).isEqualTo(BigDecimal.valueOf(exp.getTime() / 1000));
    }

    @Test
    public void encodeObject_jwt() {
        // Encode a POJO to JWT

        JWTParameters parameters = getJwtParameters();

        JWTEncoder encoder = new JWTEncoder();
        String encoded = encoder.encode(payload, parameters);

        String[] jwtParts = encoded.split("\\.");
        assertThat(jwtParts).hasSize(3);

        Map<String, Object> header = getJson(jwtParts[0]);

        assertThat(header).hasSize(3);
        assertThat(header).containsEntry("alg", "RS256");
        assertThat(header).containsEntry("kid", "kid");
        assertThat(header).containsEntry("typ", "JWT");

        Map<String, Object> content = getJson(jwtParts[1]);
        assertThat(content).hasSize(3);
        assertThat(content).containsEntry("number", BigDecimal.valueOf(42));
        assertThat(content).containsKey("myList");
        List<String> list = (List<String>) content.get("myList");
        assertThat(list).containsOnly("permission1", "permission2");
        assertThat(content).containsEntry("value", "JUnit");
    }

    private JWTParameters getJwtParameters() {
        List<AtbashKey> keys = generateRSAKeys("kid");

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        return JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keyList.get(0))
                .build();
    }

    @Test
    public void encodeObject_jwe() {
        // Encode a POJO to JWE

        AtbashKey keyForSigning = createKeyForSigning();
        AtbashKey keyForEncryption = createKeyForEncryption();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(keyForSigning)
                .withSecretKeyForEncryption(keyForEncryption)
                .build();

        JWTEncoder encoder = new JWTEncoder();
        String encoded = encoder.encode(payload, parameters);

        String[] jwtParts = encoded.split("\\.");
        assertThat(jwtParts).hasSize(5);

        Map<String, Object> header = getJson(jwtParts[0]);

        assertThat(header).hasSize(4);
        assertThat(header).containsEntry("alg", "RSA-OAEP-256");
        assertThat(header).containsEntry("kid", "encrypt");
        assertThat(header).containsEntry("cty", "JWT");
        assertThat(header).containsEntry("enc", "A256GCM");

        // The rest is really not decipherable.
    }

    private AtbashKey createKeyForSigning() {
        List<AtbashKey> keys = generateRSAKeys("sign");

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        return keyList.get(0);
    }

    private AtbashKey createKeyForEncryption() {
        List<AtbashKey> keys = generateRSAKeys("encrypt");

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Public key").hasSize(1);

        return keyList.get(0);
    }

    private Map<String, Object> getJson(String jwtPart) {
        String decoded = new String(Base64.getDecoder().decode(jwtPart));
        return new JWTDecoder().decode(decoded, HashMap.class).getData();
    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    @Test
    public void encodeWithCustomerSerializer() throws ParseException {
        JWTParameters parameters = getJwtParameters();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(new MyColor(100, 150, 200), parameters);

        JWT jwt = JWTParser.parse(json);
        assertThat(jwt.getJWTClaimsSet().getStringClaim("value")).isEqualTo("100,150,200");

    }
}