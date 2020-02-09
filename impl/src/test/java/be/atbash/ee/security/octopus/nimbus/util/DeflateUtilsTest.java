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
package be.atbash.ee.security.octopus.nimbus.util;


import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


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


        assertThat(textBytesDecompressed.length).withFailMessage("byte length check").isEqualTo(textBytes.length);
        assertThat(textDecompressed.length()).withFailMessage("text length check").isEqualTo(text.length());
        assertThat(textDecompressed).withFailMessage("text comparison").isEqualTo(text);

    }
}
