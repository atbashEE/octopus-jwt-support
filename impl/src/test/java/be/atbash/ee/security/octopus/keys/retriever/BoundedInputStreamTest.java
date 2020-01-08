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
package be.atbash.ee.security.octopus.keys.retriever;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

public class BoundedInputStreamTest {

    private static byte[] createDataArray() {

        int size = 100;
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = 1;
        }
        return data;
    }

    @Test
    public void testUnboundedConstructor() {
        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);
        BoundedInputStream bis = new BoundedInputStream(stream);
        assertThat(bis.getLimitBytes()).isEqualTo(-1L);
    }

    @Test
    public void testBounded_readIntoArray_exceed()
            throws Exception {

        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);

        final int limit = 50;

        BoundedInputStream bis = new BoundedInputStream(stream, limit);

        assertThat(bis.getLimitBytes()).isEqualTo(limit);

        byte[] readData = new byte[data.length];

        IOException e = Assertions.assertThrows(IOException.class, () -> bis.read(readData));
        assertThat(e.getMessage()).isEqualTo("Exceeded configured input limit of 50 bytes");

        assertThat(bis.available()).isEqualTo(0);
    }

    @Test
    public void testBounded_readIntoArray_notExceeded()
            throws Exception {

        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);

        final int limit = data.length + 1;

        BoundedInputStream bis = new BoundedInputStream(stream, limit);

        assertThat(bis.getLimitBytes()).isEqualTo(limit);

        byte[] readData = new byte[data.length];

        assertThat(bis.read(readData)).isEqualTo(data.length);

        assertThat(bis.available()).isEqualTo(0);
    }

    @Test
    public void testBounded_readByInt_exceed()
            throws Exception {

        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);

        final int limit = 50;

        BoundedInputStream bis = new BoundedInputStream(stream, limit);

        assertThat(bis.getLimitBytes()).isEqualTo(limit);

        for (int i = 0; i < limit; i++) {
            assertThat(bis.read()).isEqualTo(1);
        }

        IOException e = Assertions.assertThrows(IOException.class, () -> bis.read());
        assertThat(e.getMessage()).isEqualTo("Exceeded configured input limit of 50 bytes");

        assertThat(bis.available()).isEqualTo(0);
    }

    @Test
    public void testBounded_readByInt_notExceeded()
            throws Exception {

        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);

        final int limit = data.length + 1;

        BoundedInputStream bis = new BoundedInputStream(stream, limit);

        assertThat(bis.getLimitBytes()).isEqualTo(limit);

        for (int i = 0; i < limit - 1; i++) {
            assertThat(bis.read()).isEqualTo(1);
        }
        assertThat(bis.read()).isEqualTo(-1);
        assertThat(bis.available()).isEqualTo(0);
    }

    @Test
    public void testUnbounded_readByInt()
            throws Exception {

        byte[] data = createDataArray();
        InputStream stream = new ByteArrayInputStream(data);

        BoundedInputStream bis = new BoundedInputStream(stream, -1L);

        assertThat(bis.getLimitBytes()).isEqualTo(-1L);

        for (int i = 0; i < data.length; i++) {
            assertThat(bis.read()).isEqualTo(1);
        }
        assertThat(bis.read()).isEqualTo(-1);
        assertThat(bis.available()).isEqualTo(0);
    }
}