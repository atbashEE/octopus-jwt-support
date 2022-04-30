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
import be.atbash.ee.security.octopus.exception.MissingPasswordLookupException;
import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class KeyReaderKeyStore {

    // https://stackoverflow.com/questions/23629246/is-it-possible-to-create-jks-keystore-file-without-a-password
    //https://github.com/jfsulliv/JWK_Extractor/blob/master/src/jwk_extractor/JWK_Handler.java

    public List<AtbashKey> readResource(String path, KeyResourcePasswordLookup passwordLookup) {
        if (passwordLookup == null) {
            throw new MissingPasswordLookupException();
        }
        List<AtbashKey> result;

        try (InputStream inputStream = ResourceUtil.getInstance().getStream(path)) {
            // When path not found, FileNotFoundException is thrown by getStream
            result = parseContent(inputStream, path, passwordLookup);
        } catch (FileNotFoundException e) {
            throw new ResourceNotFoundException(path);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    public List<AtbashKey> parseContent(String content, KeyResourcePasswordLookup passwordLookup) {
        List<AtbashKey> result = new ArrayList<>();
        KeyStore keyStore = createKeyStore();

        try {
            InputStream inputStream = new ByteArrayInputStream(Base64.decode(content));
            keyStore.load(inputStream, passwordLookup.getResourcePassword("inline"));

            defineKeys("inline", passwordLookup, result, keyStore);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException |
                 UnrecoverableKeyException e) {
            // FIXME This needs to be tuned based on the actual exception. Not all are unexpected.
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    public List<AtbashKey> parseContent(InputStream inputStream, String path, KeyResourcePasswordLookup passwordLookup) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        List<AtbashKey> result = new ArrayList<>();
        KeyStore keyStore = createKeyStore();
        keyStore.load(inputStream, passwordLookup.getResourcePassword(path));

        defineKeys(path, passwordLookup, result, keyStore);
        return result;
    }

    private void defineKeys(String path, KeyResourcePasswordLookup passwordLookup, List<AtbashKey> keys, KeyStore keyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        for (Enumeration<String> keyAliases = keyStore.aliases(); keyAliases.hasMoreElements(); ) {
            String alias = keyAliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                char[] password = passwordLookup.getKeyPassword(path, alias);
                keys.addAll(readKeysFromKeyEntry(keyStore, alias, password));
            }
            if (keyStore.isCertificateEntry(alias)) {
                Certificate certificate = keyStore.getCertificate(alias);
                keys.add(new AtbashKey(alias, certificate.getPublicKey()));
            }

        }
    }

    private KeyStore createKeyStore() {
        KeyStore keyStore;
        try {
            String keyStoreType = JwtSupportConfiguration.getInstance().getKeyStoreType();
            if ("JKS".equals(keyStoreType)) {
                keyStore = KeyStore.getInstance(keyStoreType);
            } else {
                keyStore = KeyStore.getInstance(keyStoreType, BouncyCastleProviderSingleton.getInstance());

            }
        } catch (KeyStoreException e) {
            throw new AtbashUnexpectedException(e);
        }
        return keyStore;
    }

    private List<AtbashKey> readKeysFromKeyEntry(KeyStore keyStore, String alias, char[] password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        List<AtbashKey> result = new ArrayList<>();
        PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
        // keyId == alias -> not good, needs to take into account part of the path.

        result.add(new AtbashKey(alias, key));

        Certificate cert = keyStore.getCertificate(alias);
        PublicKey pkey = cert.getPublicKey();

        result.add(new AtbashKey(alias, pkey));

        return result;
    }

}
