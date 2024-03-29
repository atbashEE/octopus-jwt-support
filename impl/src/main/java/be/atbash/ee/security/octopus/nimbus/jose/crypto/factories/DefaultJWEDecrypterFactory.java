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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.*;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AESCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.DirectCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDHCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSACryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Default JSON Web Encryption (JWE) decrypter factory.
 *
 * <p>Supports all standard JWE algorithms implemented in the
 * {@link be.atbash.ee.security.octopus.nimbus.jose.crypto} package.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class DefaultJWEDecrypterFactory implements JWEDecrypterFactory {


    /**
     * The supported JWE algorithms.
     */
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods.
     */
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.addAll(RSACryptoProvider.SUPPORTED_ALGORITHMS);
        algs.addAll(ECDHCryptoProvider.SUPPORTED_ALGORITHMS);
        algs.addAll(DirectCryptoProvider.SUPPORTED_ALGORITHMS);
        algs.addAll(AESCryptoProvider.SUPPORTED_ALGORITHMS);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

        Set<EncryptionMethod> encs = new LinkedHashSet<>();
        encs.addAll(RSACryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(ECDHCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(DirectCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(encs);
    }


    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {

        return SUPPORTED_ALGORITHMS;
    }


    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {

        return SUPPORTED_ENCRYPTION_METHODS;
    }


    @Override
    public JWEDecrypter createJWEDecrypter(JWEHeader header, Key key) {

        JWEDecrypter decrypter;

        if (RSADecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof PrivateKey && key instanceof RSAKey)) {
                throw new KeyTypeException(PrivateKey.class, RSAKey.class);
            }

            PrivateKey rsaPrivateKey = (PrivateKey) key;

            decrypter = new RSADecrypter(rsaPrivateKey);

        } else if (ECDHDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof PrivateKey && key instanceof ECKey)) {
                throw new KeyTypeException(PrivateKey.class, ECKey.class);
            }

            PrivateKey ecPrivateKey = (PrivateKey) key;
            Curve curve = Curve.forECParameterSpec(((ECKey) key).getParams());

            decrypter = new ECDHDecrypter(ecPrivateKey, null, curve);

        } else if (DirectDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof SecretKey)) {
                throw new KeyTypeException(SecretKey.class);
            }

            SecretKey aesKey = (SecretKey) key;
            DirectDecrypter directDecrypter = new DirectDecrypter(aesKey);

            if (!directDecrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod())) {
                throw new KeyLengthException(header.getEncryptionMethod().cekBitLength(), header.getEncryptionMethod());
            }

            decrypter = directDecrypter;

        } else if (AESDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                AESDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof SecretKey)) {
                throw new KeyTypeException(SecretKey.class);
            }

            SecretKey aesKey = (SecretKey) key;
            AESDecrypter aesDecrypter = new AESDecrypter(aesKey);

            if (!aesDecrypter.supportedJWEAlgorithms().contains(header.getAlgorithm())) {
                throw new KeyLengthException(header.getAlgorithm());
            }

            decrypter = aesDecrypter;

        } else if (PasswordBasedDecrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof SecretKey)) {
                throw new KeyTypeException(SecretKey.class);
            }
            decrypter = new PasswordBasedDecrypter((SecretKey) key);

        } else {

            throw new JOSEException("Unsupported JWE algorithm or encryption method");
        }

        return decrypter;
    }
}
