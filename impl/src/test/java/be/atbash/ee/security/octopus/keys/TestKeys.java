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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.generator.*;

import java.util.List;

public final class TestKeys {

    private TestKeys() {
    }

    public static List<AtbashKey> generateRSAKeys(String kid) {
        return generateRSAKeys(kid, 2048);
    }

    public static List<AtbashKey> generateRSAKeys(String kid, int keySize) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .withKeySize(keySize)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    public static List<AtbashKey> generateECKeys(String kid) {
        return generateECKeys(kid, "P-256");
    }

    public static List<AtbashKey> generateECKeys(String kid, String curve) {
        ECGenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId(kid)
                .withCurveName(curve)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(parameters);
    }

    public static List<AtbashKey> generateOCTKeys(String kid) {
        return generateOCTKeys(kid, 256);
    }

    public static List<AtbashKey> generateOCTKeys(String kid, int length) {
        OCTGenerationParameters generationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeySize(length)
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    public static List<AtbashKey> generateOKPKeys(String kid) {
        OKPGenerationParameters generationParameters = new OKPGenerationParameters.OKPGenerationParametersBuilder()
                .withKeyId(kid)
                .build();

        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }
}
