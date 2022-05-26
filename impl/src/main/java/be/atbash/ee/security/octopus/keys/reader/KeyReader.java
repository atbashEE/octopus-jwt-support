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

    private KeyReaderKeyStore keyReaderKeyStore = new KeyReaderKeyStore();
    private KeyReaderPEM keyReaderPEM = new KeyReaderPEM();
    private KeyReaderJWK keyReaderJWK = new KeyReaderJWK();
    private KeyReaderJWKSet keyReaderJWKSet = new KeyReaderJWKSet();

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
                    try {
                        result = keyReaderJWK.parse(json, path, passwordLookup);
                    } catch (ParseException | JsonbException e) {
                        ;// Carry on with next format.
                    }
                }
                if (resourceType == KeyResourceType.JWKSET) {
                    try {
                        result = keyReaderJWKSet.parseContent(json, path, passwordLookup);
                    } catch (JsonbException e) {
                        ;// Carry on with next format.
                    }
                }
                if (resourceType == KeyResourceType.KEYSTORE) {
                    result = keyReaderKeyStore.parseContent(new ByteArrayInputStream(content), path, passwordLookup);
                }
            } catch (IOException | PKCSException | OperatorCreationException | NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
                throw new AtbashUnexpectedException(e);
            }
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
