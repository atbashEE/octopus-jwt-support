/**
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
package be.atbash.ee.security.octopus.util

import be.atbash.ee.security.octopus.DecryptionFailedException
import spock.lang.Specification

/**
 *
 */

class EncryptionHelperTest extends Specification {

    def "encode decode"() {

        when:
        char[] password = "pw".toCharArray()
        def encoded = EncryptionHelper.encode("This is the text which needs to encrypted", password)

        then:
        EncryptionHelper.decode(encoded, password) == "This is the text which needs to encrypted"
    }

    def "encode Decode - Wrong password"() {

        when:
        def encoded = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray())
        EncryptionHelper.decode(encoded, "Atbash".toCharArray()) != "This is the text which needs to encrypted"

        then:
        thrown DecryptionFailedException
    }

    def "encode No 2 encodings are the same"() {

        when:
        def encoded1 = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray())
        def encoded2 = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray())


        then:
        encoded1 != encoded2
    }

}
