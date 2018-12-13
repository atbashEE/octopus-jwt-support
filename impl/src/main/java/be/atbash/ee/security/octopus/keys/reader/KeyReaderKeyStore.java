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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

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
        List<AtbashKey> result = new ArrayList<>();

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new AtbashUnexpectedException(e);
        }
        // FIXME .getStream can return null ....
        try (InputStream inputStream = ResourceUtil.getInstance().getStream(path)) {
            keyStore.load(inputStream, passwordLookup.getResourcePassword(path));

            for (Enumeration<String> keyAliases = keyStore.aliases(); keyAliases.hasMoreElements(); ) {
                String alias = keyAliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    char[] password = passwordLookup.getKeyPassword(path, alias);
                    result.addAll(readKeysFromKeyEntry(keyStore, alias, password));
                }

            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;
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
