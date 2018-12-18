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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.List;

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

    public List<AtbashKey> readKeyResource(String path, KeyResourcePasswordLookup passwordLookup) {
        checkDependencies();

        List<AtbashKey> result ;

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

    private void checkDependencies() {
        // duplicated in KeyFilesHelper
        // for the JAVA SE Case
        if (keyResourceTypeProvider == null) {
            jwtSupportConfiguration = JwtSupportConfiguration.getInstance();
            keyResourceTypeProvider = jwtSupportConfiguration.getKeyResourceTypeProvider();
        }
    }
}
