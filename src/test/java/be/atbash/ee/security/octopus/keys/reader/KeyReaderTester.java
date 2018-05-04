/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.config.util.ResourceUtils;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;

import java.util.List;

/**
 *
 */

public class KeyReaderTester {

    public static void main(String[] args) {

        KeyReader keyReader = new KeyReader();
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtils.CLASSPATH_PREFIX + "secp256k1-key.pem", null);
        for (AtbashKey key : keys) {
            System.out.println("XXXXX");
            System.out.println("Key Id " + key.getKeyId());
            System.out.println("Key Type " + key.getSecretKeyType().getKeyType() + " - " + key.getSecretKeyType().getAsymmetricPart());
            System.out.println("Key" + key.getKey());
        }
    }

    private static class TestPasswordLookup implements KeyResourcePasswordLookup {
        private char[] password;

        public TestPasswordLookup(char[] password) {

            this.password = password;
        }

        @Override
        public char[] getResourcePassword(String path) {
            return password;
        }

        @Override
        public char[] getKeyPassword(String path, String keyId) {
            return new char[0];
        }
    }
}
