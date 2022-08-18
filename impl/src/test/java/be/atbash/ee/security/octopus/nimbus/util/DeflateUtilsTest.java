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
package be.atbash.ee.security.octopus.nimbus.util;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;


/**
 * Tests DEFLATE compression.
 *
 */
public class DeflateUtilsTest {

    @Test
    public void testDeflateAndInflate()
            throws Exception {

        String text = "Hello world!";
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

        byte[] compressed = DeflateUtils.compress(textBytes);

        byte[] textBytesDecompressed = DeflateUtils.decompress(compressed);
        String textDecompressed = new String(textBytesDecompressed, StandardCharsets.UTF_8);


        Assertions.assertThat(textBytesDecompressed.length).withFailMessage("byte length check").isEqualTo(textBytes.length);
        Assertions.assertThat(textDecompressed.length()).withFailMessage("text length check").isEqualTo(text.length());
        Assertions.assertThat(textDecompressed).withFailMessage("text comparison").isEqualTo(text);

    }
}
