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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.exception.DecryptionFailedException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptionHelperTest {

    @Test
    public void encode_decode() {

        char[] password = "pw".toCharArray();
        String encoded = EncryptionHelper.encode("This is the text which needs to encrypted", password);

        String decoded = EncryptionHelper.decode(encoded, password);

        assertThat(decoded).isEqualTo("This is the text which needs to encrypted");
    }

    @Test(expected = DecryptionFailedException.class)
    public void encode_decode_WrongPassword() {

        String encoded = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray());
        EncryptionHelper.decode(encoded, "Atbash".toCharArray());

    }

    @Test
    public void encode_No2EncodingsAreTheSame() {

        String encoded1 = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray());
        String encoded2 = EncryptionHelper.encode("This is the text which needs to encrypted", "pw".toCharArray());

        assertThat(encoded1).isNotEqualTo(encoded2);
    }

    @Test
    public void encode_decode_withAESKey() {

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        AtbashKey key = HmacSecretUtil.generateSecretKey("hmacID", secret);

        String encoded = EncryptionHelper.encode("This is the text which needs to encrypted", (SecretKey) key.getKey());

        String decoded = EncryptionHelper.decode(encoded, (SecretKey) key.getKey());

        assertThat(decoded).isEqualTo("This is the text which needs to encrypted");
    }

}