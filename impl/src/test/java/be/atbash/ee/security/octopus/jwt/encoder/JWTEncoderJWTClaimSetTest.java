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
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

// Test JWTEncoder with JWTClaimSet
public class JWTEncoderJWTClaimSetTest {

    private JWTClaimsSet jwtClaimsSet;

    @BeforeEach
    public void setup() {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("http://atbash.be")
                .audience("someClient")
                .subject("theSubject")
                .expirationTime(new Date());

        jwtClaimsSet = builder.build();
    }


    @Test
    public void encodeObject_jwt() {
        // Encode to JWT

        List<AtbashKey> keys = generateRSAKeys("kid");

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keyList.get(0))
                .build();

        JWTEncoder encoder = new JWTEncoder();
        String encoded = encoder.encode(jwtClaimsSet, parameters);

        String[] jwtParts = encoded.split("\\.");
        assertThat(jwtParts).hasSize(3);

        Map<String, Object> header = getJson(jwtParts[0]);

        assertThat(header).hasSize(3);
        assertThat(header).containsEntry("alg", "RS256");
        assertThat(header).containsEntry("kid", "kid");
        assertThat(header).containsEntry("typ", "JWT");

        Map<String, Object> content = getJson(jwtParts[1]);
        assertThat(content).hasSize(4);
        assertThat(content).containsEntry("iss", "http://atbash.be");
        assertThat(content).containsEntry("aud", "someClient");
        assertThat(content).containsEntry("sub", "theSubject");
        assertThat(content).containsKey("exp");

    }

    @Test
    public void encodeObject_jwe() {
        // Encode to JWE

        AtbashKey keyForSigning = createKeyForSigning();
        AtbashKey keyForEncryption = createKeyForEncryption();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(keyForSigning)
                .withSecretKeyForEncryption(keyForEncryption)
                .build();

        JWTEncoder encoder = new JWTEncoder();
        String encoded = encoder.encode(jwtClaimsSet, parameters);

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

}