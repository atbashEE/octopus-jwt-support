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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.util.CDIUtils;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.bind.JsonbException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@PublicAPI
@ApplicationScoped
public class KeyReader {

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    private KeyResourceTypeProvider keyResourceTypeProvider;

    private final KeyReaderKeyStore keyReaderKeyStore = new KeyReaderKeyStore();
    private final KeyReaderPEM keyReaderPEM = new KeyReaderPEM();
    private final KeyReaderJWK keyReaderJWK = new KeyReaderJWK();
    private final KeyReaderJWKSet keyReaderJWKSet = new KeyReaderJWKSet();

    @PostConstruct
    public void init() {
        keyResourceTypeProvider = CDIUtils.retrieveOptionalInstance(KeyResourceTypeProvider.class);

        // No developer defined CDI instance, use the config defined one (is the default if not specified).
        if (keyResourceTypeProvider == null) {
            keyResourceTypeProvider = jwtSupportConfiguration.getKeyResourceTypeProvider();
        }
    }

    public List<AtbashKey> readKeyResource(KeyResourceType keyResourceType, String path) {
        return this.readKeyResource(keyResourceType, path, null);
    }

    public List<AtbashKey> readKeyResource(KeyResourceType keyResourceType, String path, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();

        List<AtbashKey> result;

        switch (keyResourceType) {

            case JWK:
                result = keyReaderJWK.readResource(path, passwordLookup);
                break;
            case JWKSET:
                result = keyReaderJWKSet.readResource(path, passwordLookup);
                break;
            case PEM:
                result = keyReaderPEM.readResource(path, passwordLookup);
                break;
            case KEYSTORE:
                result = keyReaderKeyStore.readResource(path, passwordLookup);
                break;
            default:
                throw new IllegalArgumentException(String.format("Unknown KeyResourceType %s", keyResourceType));
        }

        return result;
    }

    public List<AtbashKey> readKeyResource(String path) {
        return this.readKeyResource(path, null);
    }

    public List<AtbashKey> readKeyResource(String path, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();

        List<AtbashKey> result;

        KeyResourceType keyResourceType = keyResourceTypeProvider.determineKeyResourceType(path);
        if (keyResourceType == null) {
            throw new UnknownKeyResourceTypeException(path);
        }
        switch (keyResourceType) {

            case JWK:
                result = keyReaderJWK.readResource(path, passwordLookup);
                break;
            case JWKSET:
                result = keyReaderJWKSet.readResource(path, passwordLookup);
                break;
            case PEM:
                result = keyReaderPEM.readResource(path, passwordLookup);
                break;
            case KEYSTORE:
                result = keyReaderKeyStore.readResource(path, passwordLookup);
                break;
            default:
                throw new IllegalArgumentException(String.format("Unknown KeyResourceType %s", keyResourceType));
        }

        return result;
    }

    /**
     * This is not a performant implementation as it tries PEM, JWK, KeyStore and JWKSet to read the resource.
     * This should only be used as a fallback  {@code  KeyReader#readKeyResource(java.lang.String, be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup)}
     * indicates that the type could not be determined (UnknownKeyResourceTypeException because the file doesn't have an extension)
     *
     * @param path
     * @param passwordLookup
     * @return
     */
    public List<AtbashKey> tryToReadKeyResource(String path, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();

        boolean matched = false;
        List<AtbashKey> result = new ArrayList<>();
        try {
            result = keyReaderPEM.readResource(path, passwordLookup);
            matched = !result.isEmpty();
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }

        if (matched) {
            return result;
        }

        try {
            result = keyReaderJWK.readResource(path, passwordLookup);
            matched = !result.isEmpty();
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }
        if (matched) {
            return result;
        }

        try {
            result = keyReaderJWKSet.readResource(path, passwordLookup);
            matched = !result.isEmpty();
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }
        if (matched) {
            return result;
        }

        try {
            result = keyReaderKeyStore.readResource(path, passwordLookup);
            matched = true;
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }
        if (matched) {
            return result;
        }

        try {
            result = keyReaderJWKSet.readResource(path, passwordLookup);
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }

        return result;
    }

    /**
     * This is not a performant implementation as it tries PEM, JWK, KeyStore and JWKSet to read the resource and mainly only of any significance
     * with MicroProfile JWT Specification. It is not recommended to define the entire key as a string in a property value.
     * The Keystore format needs to be Base64 encoded and password is looked up with 'inline' as 'path' value
     *
     * @param content
     * @return
     */
    public List<AtbashKey> tryToReadKeyContent(String content) {
        return tryToReadKeyContent(content, null);
    }

    /**
     * This is not a performant implementation as it tries PEM, JWK, KeyStore and JWKSet to read the resource and mainly only of any significance
     * with MicroProfile JWT Specification. It is not recommended to define the entire key as a string in a property value.
     * The Keystore format needs to be Base64 encoded and password is looked up with 'inline' as 'path' value
     *
     * @param content
     * @param passwordLookup
     * @return
     */
    public List<AtbashKey> tryToReadKeyContent(String content, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();

        boolean matched = false;
        List<AtbashKey> result = new ArrayList<>();
        try {
            result = keyReaderPEM.parseContent(content, passwordLookup);
            matched = !result.isEmpty();  // When not PEM data, the method returns an empty list and not an exception.
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }

        if (matched) {
            return result;
        }

        try {
            result = keyReaderJWK.parseContent(content, passwordLookup);
            matched = !result.isEmpty();  // When  a JWKS is read by keyReaderJWK, it returns empty list.
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }
        if (matched) {
            return result;
        }

        try {
            result = keyReaderJWKSet.parseContent(content, "inline", passwordLookup);
            matched = !result.isEmpty();
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }
        if (matched) {
            return result;
        }

        try {
            result = keyReaderKeyStore.parseContent(content, passwordLookup);
        } catch (AtbashUnexpectedException e) {
            // Capture exception and try next format.
        }

        return result;
    }

    /**
     * @param uri
     * @param passwordLookup
     * @return
     */
    public List<AtbashKey> readKeyResource(URI uri, KeyResourcePasswordLookup passwordLookup) {
        URL url;
        InputStream stream;
        try {
            url = uri.toURL();

            stream = url.openStream();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        return readKeyResource(stream, uri.toASCIIString(), passwordLookup);
    }

    /**
     * @param stream
     * @param passwordLookup
     * @return
     */
    public List<AtbashKey> readKeyResource(InputStream stream, String path, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();
        List<AtbashKey> result = new ArrayList<>();
        byte[] content;
        try {
            content = ByteUtils.readAllBytes(stream);
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        List<KeyResourceType> order = jwtSupportConfiguration.getReaderOrder();

        String json = new String(content);

        Iterator<KeyResourceType> iterator = order.iterator();
        while (iterator.hasNext() && result.isEmpty()) {
            KeyResourceType resourceType = iterator.next();
            try {
                if (resourceType == KeyResourceType.PEM) {
                    result.addAll(keyReaderPEM.parseContent(new InputStreamReader(new ByteArrayInputStream(content)), path, passwordLookup));
                }

                if (resourceType == KeyResourceType.JWK) {
                    result = parseFromJWK(path, passwordLookup, result, json);
                }
                if (resourceType == KeyResourceType.JWKSET) {
                    result = parseFromJWKSet(path, passwordLookup, result, json);
                }
                if (resourceType == KeyResourceType.KEYSTORE) {
                    result = keyReaderKeyStore.parseContent(new ByteArrayInputStream(content), path, passwordLookup);
                }
            } catch (IOException | PKCSException | OperatorCreationException | NoSuchAlgorithmException |
                     CertificateException | KeyStoreException | UnrecoverableKeyException e) {
                throw new AtbashUnexpectedException(e);
            }
        }

        return result;
    }

    private List<AtbashKey> parseFromJWKSet(String path, KeyResourcePasswordLookup passwordLookup, List<AtbashKey> result, String json) {
        try {
            result = keyReaderJWKSet.parseContent(json, path, passwordLookup);
        } catch (JsonbException e) {
            // Carry on with next format.
        }
        return result;
    }

    private List<AtbashKey> parseFromJWK(String path, KeyResourcePasswordLookup passwordLookup, List<AtbashKey> result, String json) {
        try {
            result = keyReaderJWK.parse(json, path, passwordLookup);
        } catch (ParseException | JsonbException e) {
            // Carry on with next format.
        }
        return result;
    }


    private void checkDependencies() {
        // duplicated in KeyFilesHelper
        // for the JAVA SE Case
        if (keyResourceTypeProvider == null) {
            jwtSupportConfiguration = JwtSupportConfiguration.getInstance();
            keyResourceTypeProvider = jwtSupportConfiguration.getKeyResourceTypeProvider();
        }
    }
}
