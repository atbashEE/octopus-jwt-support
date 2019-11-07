/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jwk;

import be.atbash.ee.security.octopus.nimbus.IOUtil;

import java.net.URISyntaxException;
import java.net.URL;

public final class SamplePEMEncodedObjects {

    // openssl ecparam -name secp256r1 -genkey -noout -out src/test/resources/ecprivkey.pem
    private static final URL EC_PRIVATE_KEY_PEM_URL = getResource("ecprivkey.pem");
    // openssl ec -in src/test/resources/ecprivkey.pem -pubout -out src/test/resources/ecpubkey.pem
    private static final URL EC_PUBLIC_KEY_PEM_URL = getResource("ecpubkey.pem");
    // openssl req -new -x509 -key src/test/resources/ecprivkey.pem -days 1095 -out src/test/resources/eccert.pem
    private static final URL EC_CERT_PEM_URL = getResource("eccert.pem");

    // openssl genpkey -algorithm RSA -out src/test/resources/rsaprivkey.pem -pkeyopt rsa_keygen_bits:2048
    private static final URL RSA_PRIVATE_KEY_PEM_URL = getResource("rsaprivkey.pem");
    // openssl rsa -pubout -in src/test/resources/rsaprivkey.pem -out src/test/resources/rsapubkey.pem
    private static final URL RSA_PUBLIC_KEY_PEM_URL = getResource("rsapubkey.pem");
    // openssl req -new -x509 -key src/test/resources/rsaprivkey.pem -days 1095 -out src/test/resources/rsacert.pem
    private static final URL RSA_CERT_PEM_URL = getResource("rsacert.pem");

    public static final String EC_PRIVATE_KEY_PEM = loadUrl(EC_PRIVATE_KEY_PEM_URL);
    public static final String EC_PUBLIC_KEY_PEM = loadUrl(EC_PUBLIC_KEY_PEM_URL);
    public static final String EC_CERT_PEM = loadUrl(EC_CERT_PEM_URL);
    public static final String RSA_PRIVATE_KEY_PEM = loadUrl(RSA_PRIVATE_KEY_PEM_URL);
    public static final String RSA_PUBLIC_KEY_PEM = loadUrl(RSA_PUBLIC_KEY_PEM_URL);
    public static final String RSA_CERT_PEM = loadUrl(RSA_CERT_PEM_URL);

    private static URL getResource(final String resourceName) {
        final ClassLoader loader = SamplePEMEncodedObjects.class.getClassLoader();
        return loader.getResource("sample-pem-encoded-objects/" + resourceName);
    }

    private static String loadUrl(final URL url) {
        try {
            return IOUtil.readURIToString(url.toURI());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Couldn't read URL " + url, e);
        }
    }
}
