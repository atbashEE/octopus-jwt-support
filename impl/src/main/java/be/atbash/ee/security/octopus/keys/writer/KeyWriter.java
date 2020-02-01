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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.config.PemKeyEncryption;
import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Scanner;

import static be.atbash.ee.security.octopus.exception.MissingPasswordException.ObjectType.STORE;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class KeyWriter {

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    @Inject
    private KeyWriterFactory keyWriterFactory;

    @Inject
    private ResourceUtil resourceUtil;

    public void writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType, String target) {
        this.writeKeyResource(atbashKey, keyResourceType, target, null, null);
    }

    public void writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType, String target, char[] keyPasssword) {
        this.writeKeyResource(atbashKey, keyResourceType, target, keyPasssword, null);
    }

    public void writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType, String target, char[] keyPasssword, char[] filePassword) {
        checkDependencies();
        try {
            byte[] content;
            switch (keyResourceType) {

                case JWK:
                    checkTargetFile(target, true);
                    content = writeKeyAsJWK(atbashKey, keyPasssword);
                    writeFile(target, content);
                    break;
                case JWKSET:
                    checkTargetFile(target, false);
                    JWKSet jwkSet = loadExistingJWKSet(target);

                    content = writeKeyAsJWKSet(atbashKey, jwkSet);
                    writeFile(target, content);
                    break;
                case PEM:
                    checkTargetFile(target, true);
                    content = writeKeyAsPEM(atbashKey, keyPasssword);
                    writeFile(target, content);
                    break;
                case KEYSTORE:
                    checkTargetFile(target, false);

                    KeyStore keyStore = loadExistingKeyStore(target, filePassword);

                    content = writeKeyAsKeyStore(atbashKey, keyPasssword, filePassword, keyStore);
                    writeFile(target, content);
                    break;
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            // TODO org.bouncycastle.util.io.pem.PemGenerationException: encoding exception: unknown encryption with private key
            // -> Custom exception

            throw new AtbashUnexpectedException(e);
        }
    }

    private byte[] writeKeyAsJWKSet(AtbashKey atbashKey, JWKSet jwkSet) {
        KeyEncoderParameters parameters = new KeyEncoderParameters(jwkSet);

        return keyWriterFactory.writeKeyAsJWKSet(atbashKey, parameters);

    }

    private JWKSet loadExistingJWKSet(String target) {
        JWKSet result;
        InputStream inputStream = null;
        try {
            if (resourceUtil.resourceExists(target)) {
                inputStream = resourceUtil.getStream(target);
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        if (inputStream == null) {
            result = new JWKSet();
        } else {

            String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();
            try {
                result = JWKSet.parse(fileContent);
            } catch (ParseException e) {
                // TODO We need another exception, indicating that loading failed
                throw new AtbashUnexpectedException(e);
            } finally {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }
        return result;
    }

    private KeyStore loadExistingKeyStore(String target, char[] filePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(jwtSupportConfiguration.getKeyStoreType(), BouncyCastleProviderSingleton.getInstance());

        if (resourceUtil.resourceExists(target)) {

            InputStream inputStream = resourceUtil.getStream(target);
            keyStore.load(inputStream, filePassword);
        } else {

            keyStore.load(null, null);
        }
        return keyStore;
    }

    private void writeFile(String target, byte[] fileContent) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(target)) {
            outputStream.write(fileContent);
        }
    }

    public byte[] writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType) {
        return this.writeKeyResource(atbashKey, keyResourceType, (char[])null, null);
    }

    public byte[] writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType, char[] keyPassword) {
        return this.writeKeyResource(atbashKey, keyResourceType, keyPassword, null);
    }

    public byte[] writeKeyResource(AtbashKey atbashKey, KeyResourceType keyResourceType, char[] keyPassword, char[] filePassword) {
        checkDependencies();
        byte[] result;
        try {
            switch (keyResourceType) {

                case JWK:
                    // FIXME support for encrypted JWK of Atbash (see JWKEncryptedCreator)
                    result = writeKeyAsJWK(atbashKey, keyPassword);
                    break;
                case JWKSET:
                    result = writeKeyAsJWKSet(atbashKey, new JWKSet());
                    break;
                case PEM:
                    result = writeKeyAsPEM(atbashKey, keyPassword);
                    break;
                case KEYSTORE:
                    KeyStore keyStore = KeyStore.getInstance(jwtSupportConfiguration.getKeyStoreType());
                    keyStore.load(null, null);

                    result = writeKeyAsKeyStore(atbashKey, keyPassword, filePassword, keyStore);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unsupported value for KeyResourceType : %s", keyResourceType));
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            // TODO org.bouncycastle.util.io.pem.PemGenerationException: encoding exception: unknown encryption with private key
            // -> Custom exception
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    private byte[] writeKeyAsPEM(AtbashKey atbashKey, char[] keyPassword) throws IOException {
        if (jwtSupportConfiguration.getPemKeyEncryption() != PemKeyEncryption.NONE) {

            boolean checkRequired = true;
            if (jwtSupportConfiguration.getPemKeyEncryption() == PemKeyEncryption.PKCS1 && StringUtils.isEmpty(jwtSupportConfiguration.getPKCS1EncryptionAlgorithm())) {
                checkRequired = false;
            }

            if (checkRequired) {
                // Only when encrypting the key, we need to check the password/passphrase.
                checkKeyPassword(atbashKey, keyPassword);
            }
        }

        KeyEncoderParameters parameters = new KeyEncoderParameters(keyPassword);
        parameters.addValue(PemKeyEncryption.class, jwtSupportConfiguration.getPemKeyEncryption());
        parameters.addValue("PKCS1.encryption", jwtSupportConfiguration.getPKCS1EncryptionAlgorithm());

        return keyWriterFactory.writeKeyAsPEM(atbashKey, parameters);
    }

    private byte[] writeKeyAsKeyStore(AtbashKey atbashKey, char[] keyPassword, char[] filePassword, KeyStore keyStore) throws IOException {
        checkKeyPassword(atbashKey, keyPassword);
        if (StringUtils.isEmpty(filePassword)) {
            throw new MissingPasswordException(STORE, "A password for the keystore is required in order to save the key info");
        }

        KeyEncoderParameters parameters = new KeyEncoderParameters(keyPassword, filePassword, keyStore);

        return keyWriterFactory.writeKeyAsKeyStore(atbashKey, parameters);
    }

    private byte[] writeKeyAsJWK(AtbashKey atbashKey, char[] keyPassword) {
        //checkKeyPassword(atbashKey, keyPassword);

        KeyEncoderParameters parameters = new KeyEncoderParameters(keyPassword);

        return keyWriterFactory.writeKeyAsJWK(atbashKey, parameters);
    }

    private void checkTargetFile(String target, boolean existingCheck) {
        // existingCheck -> for KeyStore / JWKSet type, the file may already be existing but must the readable and writable
        // other types -> no overwrite possible and must be writable.
        File file = new File(target);
        if (file.isDirectory()) {
            throw new KeyResourceLocationException(String.format("Location '%s' denotes a directory and must point to a file", target));
        }
        if (existingCheck) {
            if (file.exists()) {
                throw new KeyResourceLocationException(String.format("File '%s' already exists and overwrite is not allowed for this key resource type", target));
            }
        }
        boolean fileExists = file.exists();
        if (fileExists) {
            if (!file.canWrite()) {
                throw new KeyResourceLocationException(String.format("File '%s' must be writable", target));
            }
        }
        if (!fileExists) {

            File parentDirectory = file.getParentFile();
            if (!parentDirectory.exists()) {
                if (!parentDirectory.mkdirs()) {
                    throw new AtbashUnexpectedException(String.format("Directory %s could not be created", parentDirectory.getAbsolutePath()));
                }
            }
        } else {
            if (!file.canRead() || !file.canWrite()) {
                throw new KeyResourceLocationException(String.format("File '%s' must be readable and writable", target));
            }

        }

    }

    private void checkKeyPassword(AtbashKey atbashKey, char[] keyPasssword) {
        if (atbashKey.getSecretKeyType().isAsymmetric() && atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
            if (StringUtils.isEmpty(keyPasssword)) {
                throw new MissingPasswordException(STORE, "A passphrase is required in order to save the key info");
            }
        }
    }

    private void checkDependencies() {
        // for the JAVA SE Case
        if (keyWriterFactory == null) {
            keyWriterFactory = new KeyWriterFactory();
            keyWriterFactory.init();
            jwtSupportConfiguration = JwtSupportConfiguration.getInstance();
            resourceUtil = ResourceUtil.getInstance();
        }
    }

}
