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


import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.text.ParseException;
import java.util.NoSuchElementException;
import java.util.Scanner;


/**
 * The default retriever of resources specified by URL. Provides setting of a
 * HTTP proxy, HTTP connect and read timeouts as well as a size limit of the
 * retrieved entity. Caching header directives are not honoured.
 * <p>
 * Based on code by Vladimir Dzhuvinov and Artun Subasi
 */
public class JWKSetRetriever {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWKSetRetriever.class);
    private static final String PARSING_FAILED = "Parsing of content of '%s' failed";

    /**
     * The proxy to use when opening the HttpURLConnection. Can be
     * {@code null}.
     */
    private Proxy proxy;

    /**
     * The HTTP connect timeout, in milliseconds.
     */
    private int connectTimeout;


    /**
     * The HTTP read timeout, in milliseconds.
     */
    private int readTimeout;


    /**
     * The HTTP entity size limit, in bytes.
     */
    private int sizeLimit;

    /**
     * Creates a new resource retriever. The HTTP timeouts and entity size
     * limit are set to zero (infinite).
     */
    public JWKSetRetriever() {

        this(0, 0);
    }


    /**
     * Creates a new resource retriever. The HTTP entity size limit is set
     * to zero (infinite).
     *
     * @param connectTimeout The HTTP connects timeout, in milliseconds,
     *                       zero for infinite. Must not be negative.
     * @param readTimeout    The HTTP read timeout, in milliseconds, zero
     *                       for infinite. Must not be negative.
     */
    public JWKSetRetriever(int connectTimeout, int readTimeout) {

        this(connectTimeout, readTimeout, 0);
    }


    /**
     * Creates a new resource retriever.
     *
     * @param connectTimeout The HTTP connects timeout, in milliseconds,
     *                       zero for infinite. Must not be negative.
     * @param readTimeout    The HTTP read timeout, in milliseconds, zero
     *                       for infinite. Must not be negative.
     * @param sizeLimit      The HTTP entity size limit, in bytes, zero for
     *                       infinite. Must not be negative.
     */
    public JWKSetRetriever(int connectTimeout, int readTimeout, int sizeLimit) {

        setConnectTimeout(connectTimeout);
        setReadTimeout(readTimeout);
        setSizeLimit(sizeLimit);
    }

    /**
     * Returns the HTTP proxy to use when opening the HttpURLConnection to
     * retrieve the resource. Note that the JVM may have a system wide
     * proxy configured via the {@code https.proxyHost} Java system
     * property.
     *
     * @return The proxy to use or {@code null} if no proxy should be used.
     */
    public Proxy getProxy() {

        return proxy;
    }

    /**
     * Sets the HTTP proxy to use when opening the HttpURLConnection to
     * retrieve the resource. Note that the JVM may have a system wide
     * proxy configured via the {@code https.proxyHost} Java system
     * property.
     *
     * @param proxy The proxy to use or {@code null} if no proxy should be
     *              used.
     */
    public void setProxy(Proxy proxy) {

        this.proxy = proxy;
    }


    private void setConnectTimeout(int connectTimeoutMs) {

        if (connectTimeoutMs < 0) {
            throw new IllegalArgumentException("The connect timeout must not be negative");
        }

        this.connectTimeout = connectTimeoutMs;
    }

    private void setReadTimeout(int readTimeoutMs) {

        if (readTimeoutMs < 0) {
            throw new IllegalArgumentException("The read timeout must not be negative");
        }

        this.readTimeout = readTimeoutMs;
    }

    private void setSizeLimit(int sizeLimitBytes) {

        if (sizeLimitBytes < 0) {
            throw new IllegalArgumentException("The size limit must not be negative");
        }

        this.sizeLimit = sizeLimitBytes;
    }

    public JWKSet retrieveResource(URL url) throws IOException {

        HttpURLConnection connection = null;
        try {
            connection = openConnection(url);

            connection.setConnectTimeout(connectTimeout);
            connection.setReadTimeout(readTimeout);

            String content;
            try (InputStream inputStream = getInputStream(connection, sizeLimit)) {
                try {
                    content = new Scanner(inputStream).useDelimiter("\\Z").next();
                } catch (NoSuchElementException e) {
                    LOGGER.warn(String.format(PARSING_FAILED, url.toExternalForm()));
                    throw new IOException(String.format(PARSING_FAILED, url.toExternalForm()));
                }
            }

            // Check HTTP code + message
            int statusCode = connection.getResponseCode();
            String statusMessage = connection.getResponseMessage();

            // Ensure 2xx status code
            if (statusCode > 299 || statusCode < 200) {
                throw new IOException("HTTP " + statusCode + ": " + statusMessage);
            }

            return JWKSet.parse(content);

        } catch (ParseException e) {
            LOGGER.warn(String.format(PARSING_FAILED, url.toExternalForm()));
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Opens a connection the specified HTTP(S) URL. Uses the configured
     * {@link Proxy} if available.
     *
     * @param url The URL of the resource. Its scheme must be HTTP or
     *            HTTPS. Must not be {@code null}.
     * @return The opened HTTP(S) connection
     * @throws IOException If the HTTP(S) connection to the specified URL
     *                     failed.
     */
    protected HttpURLConnection openConnection(URL url) throws IOException {
        if (proxy != null) {
            return (HttpURLConnection) url.openConnection(proxy);
        } else {
            return (HttpURLConnection) url.openConnection();
        }
    }


    private InputStream getInputStream(HttpURLConnection con, final int sizeLimit)
            throws IOException {

        InputStream inputStream = con.getInputStream();

        return sizeLimit > 0 ? new BoundedInputStream(inputStream, sizeLimit) : inputStream;
    }
}
