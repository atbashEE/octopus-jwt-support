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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.SingleKeySelector;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTDecoderJWTClaimSetTest {

    private static final String KID_SIGN = "kid";
    private JWTClaimsSet jwtClaimsSet;

    private JWTDecoder decoder = new JWTDecoder();

    private JWTEncoder encoder = new JWTEncoder();

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
        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        String encoded = encoder.encode(jwtClaimsSet, getJwtParameters(keys));

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        JWTClaimsSet claimsSet = new JWTDecoder().decode(encoded, JWTClaimsSet.class, keySelector).getData();

        Map<String, Object> data = claimsSet.getClaims();
        Map<String, Object> expected = jwtClaimsSet.getClaims();
        assertThat(data.keySet()).isEqualTo(expected.keySet());
        for (String key : expected.keySet()) {
            if ("exp".equals(key)) {
                // For exp, there is a rounding in JSON, so millisecond differ.
                Date date = (Date) data.get(key);
                Date expectedDate = (Date) expected.get(key);
                assertThat(date).isCloseTo(expectedDate, 1000);
            } else {
                assertThat(data.get(key)).isEqualTo(expected.get(key));
            }
        }

    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private JWTParameters getJwtParameters(List<AtbashKey> keys) {

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        return JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keyList.get(0))
                .build();
    }

}