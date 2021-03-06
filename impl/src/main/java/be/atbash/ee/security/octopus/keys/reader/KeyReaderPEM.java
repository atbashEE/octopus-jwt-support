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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.ee.security.octopus.exception.MissingPasswordLookupException;
import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class KeyReaderPEM {
    public List<AtbashKey> readResource(String path, KeyResourcePasswordLookup passwordLookup) {
        List<AtbashKey> result;

        try {
            ResourceUtil resourceUtil = ResourceUtil.getInstance();
            if (!resourceUtil.resourceExists(path)) {
                throw new ResourceNotFoundException(path);
            }

            InputStream inputStream = resourceUtil.getStream(path);
            if (inputStream == null) {
                throw new KeyResourceNotFoundException(path);
            }
            Reader reader = new InputStreamReader(inputStream);

            result = parseContent(reader, path, passwordLookup);
        } catch (IOException | PKCSException | OperatorCreationException e) {
            throw new AtbashUnexpectedException(e);
        }

        return result;
    }

    protected List<AtbashKey> parseContent(Reader reader, String path, KeyResourcePasswordLookup passwordLookup) throws IOException, OperatorCreationException, PKCSException {

        List<AtbashKey> result = new ArrayList<>();

        PEMParser pemParser = new PEMParser(reader);
        Object pemData = pemParser.readObject();
        reader.close();

        Provider provider = BouncyCastleProviderSingleton.getInstance();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
        if (pemData instanceof PEMEncryptedKeyPair) {
            if (passwordLookup == null) {
                throw new MissingPasswordLookupException();
            }

            // Encrypted key - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) pemData;

            char[] passphrase = passwordLookup.getResourcePassword(path);
            if (StringUtils.isEmpty(passphrase)) {
                throw new MissingPasswordException(MissingPasswordException.ObjectType.STORE, path);
            }

            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().setProvider(provider).build(passphrase);

            // Untested for EC key due to https://github.com/kaikramer/keystore-explorer/issues/119
            PEMKeyPair keyPair = ckp.decryptKeyPair(decProv);
            KeyPair pair = converter.getKeyPair(keyPair);
            result.add(new AtbashKey(path, pair.getPrivate()));
            result.add(new AtbashKey(path, pair.getPublic()));
        }
        if (pemData instanceof PKCS8EncryptedPrivateKeyInfo) {
            if (passwordLookup == null) {
                throw new MissingPasswordLookupException();
            }

            PKCS8EncryptedPrivateKeyInfo privateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemData;

            JceOpenSSLPKCS8DecryptorProviderBuilder providerBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            providerBuilder.setProvider(provider);
            char[] passphrase = passwordLookup.getResourcePassword(path);

            if (StringUtils.isEmpty(passphrase)) {
                throw new MissingPasswordException(MissingPasswordException.ObjectType.STORE, path);
            }

            InputDecryptorProvider inputDecryptorProvider = providerBuilder.build(passphrase);
            PrivateKeyInfo info = privateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
            PrivateKey privateKey = converter.getPrivateKey(info);
            result.add(new AtbashKey(path, privateKey));

        }
        // Unencrypted key - no password needed
        if (pemData instanceof SubjectPublicKeyInfo) {
            PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) pemData);
            result.add(new AtbashKey(path, publicKey));

        }
        if (pemData instanceof PEMKeyPair) {
            PEMKeyPair keyPair = (PEMKeyPair) pemData;
            PrivateKey privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            PublicKey publicKey = converter.getPublicKey(keyPair.getPublicKeyInfo());
            result.add(new AtbashKey(path, privateKey));
            result.add(new AtbashKey(path, publicKey));
        }

        return result;
    }
}
