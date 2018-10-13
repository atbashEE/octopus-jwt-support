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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;

/**
 *
 */
public class TestPasswordLookup implements KeyResourcePasswordLookup {

    private char[] password = new char[0];
    private char[] kidPassword = new char[0];

    // For the test and when no passwords needed at all
    public TestPasswordLookup() {
    }

    public TestPasswordLookup(char[] password) {
        this.password = password;
    }

    public TestPasswordLookup(char[] password, char[] kidPassword) {
        this.password = password;
        this.kidPassword = kidPassword;
    }

    @Override
    public char[] getResourcePassword(String path) {
        return password;
    }

    @Override
    public char[] getKeyPassword(String path, String keyId) {
        return kidPassword;
    }
}
