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
package be.atbash.ee.security.octopus.keys.retriever;


import java.io.IOException;
import java.io.InputStream;


/**
 * Size-bounded input stream. Adapted from Apache Commons IO. Throws an
 * {@link IOException} if the input size limit is exceeded.
 */
public class BoundedInputStream extends InputStream {


    private static final String LIMIT_OF_BYTES = "Exceeded configured input limit of %s bytes.";

    /**
     * The wrapped input stream.
     */
    private final InputStream in;


    /**
     * The limit, -1 if none.
     */
    private final long max;


    /**
     * The current input stream position.
     */
    private long pos;


    /**
     * Marks the input stream.
     */
    private long mark;


    /**
     * Creates a new bounded input stream.
     *
     * @param in   The input stream to wrap.
     * @param size The maximum number of bytes to return, -1 if no limit.
     */
    public BoundedInputStream(InputStream in, long size) {
        pos = 0L;
        mark = -1L;
        max = size;
        this.in = in;
    }


    /**
     * Creates a new unbounded input stream.
     *
     * @param in The input stream to wrap.
     */
    public BoundedInputStream(InputStream in) {
        this(in, -1L);
    }


    /**
     * Returns the maximum number of bytes to return.
     *
     * @return The maximum number of bytes to return, -1 if no limit.
     */
    public long getLimitBytes() {
        return max;
    }


    @Override
    public int read() throws IOException {
        if (max >= 0L && pos >= max) {
            throw new IOException(String.format(LIMIT_OF_BYTES, max));
        } else {
            int result = in.read();
            ++pos;
            return result; // data or -1 on EOF
        }
    }


    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }


    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (max >= 0L && pos >= max) {
            throw new IOException(String.format(LIMIT_OF_BYTES, max));
        } else {
            int bytesRead = in.read(b, off, len);

            if (bytesRead == -1) {
                return -1;
            } else {
                pos += bytesRead;

                if (max >= 0L && pos >= max) {
                    throw new IOException(String.format(LIMIT_OF_BYTES, max));
                }

                return bytesRead;
            }
        }
    }


    @Override
    public long skip(long n) throws IOException {
        long toSkip = max >= 0L ? Math.min(n, max - pos) : n;
        long skippedBytes = in.skip(toSkip);
        pos += skippedBytes;
        return skippedBytes;
    }


    @Override
    public int available() throws IOException {
        return max >= 0L && pos >= max ? 0 : in.available();
    }


    @Override
    public String toString() {
        return in.toString();
    }


    @Override
    public void close() throws IOException {
        in.close();
    }


    @Override
    public synchronized void reset() throws IOException {
        in.reset();
        pos = mark;
    }


    @Override
    public synchronized void mark(int readLimit) {
        in.mark(readLimit);
        mark = this.pos;
    }


    @Override
    public boolean markSupported() {
        return in.markSupported();
    }


}
