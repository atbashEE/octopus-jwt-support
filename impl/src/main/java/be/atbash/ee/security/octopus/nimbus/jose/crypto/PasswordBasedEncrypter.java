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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AESKW;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ContentCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.PasswordBasedCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;


/**
 * Password-based encrypter of {@link JWEObject JWE objects}.
 * Expects a password.
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.8">section 4.8</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#PBES2_HS256_A128KW}
 *     <li>{@link  JWEAlgorithm#PBES2_HS384_A192KW}
 *     <li>{@link  JWEAlgorithm#PBES2_HS512_A256KW}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link EncryptionMethod#A128CBC_HS256}
 *     <li>{@link EncryptionMethod#A192CBC_HS384}
 *     <li>{@link EncryptionMethod#A256CBC_HS512}
 *     <li>{@link EncryptionMethod#A128GCM}
 *     <li>{@link EncryptionMethod#A192GCM}
 *     <li>{@link EncryptionMethod#A256GCM}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-07-26
 */

public class PasswordBasedEncrypter extends PasswordBasedCryptoProvider implements JWEEncrypter {


	/**
	 * The minimum salt length (8 bytes).
	 */
	public static final int MIN_SALT_LENGTH = 8;


	/**
	 * The cryptographic salt length, in bytes.
	 */
	//private final int saltLength;


	/**
	 * The minimum recommended iteration count (1000).
	 */
	public static final int MIN_RECOMMENDED_ITERATION_COUNT = 1000;


	/**
	 * The iteration count.
	 */
	//private final int iterationCount;


	/**
	 * Creates a new password-based encrypter.
	 *
	 * @param password       The password bytes. Must not be empty or
	 *                       {@code null}.
	 * @param saltLength     The length of the generated cryptographic
	 *                       salts, in bytes. Must be at least 8 bytes.
	 * @param iterationCount The pseudo-random function (PRF) iteration
	 *                       count. Must be at least 1000.
	 */
	public PasswordBasedEncrypter(SecretKey secretKey) {

		super(secretKey);

	}

	@Override
	public JWECryptoParts encrypt(JWEHeader header, byte[] clearText)
			throws JOSEException {

		EncryptionMethod enc = header.getEncryptionMethod();

		// FIXME We need to work on the header
		/*
		JWEHeader updatedHeader = new JWEHeader.Builder(header).
				pbes2Salt(Base64URLValue.encode(salt)).
				pbes2Count(iterationCount).
				build();

		 */
		JWEHeader updatedHeader = header;

		SecretKey cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());

		// The second JWE part
		Base64URLValue encryptedKey = Base64URLValue.encode(AESKW.wrapCEK(cek, secretKey, getJCAContext().getKeyEncryptionProvider()));

		return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
	}

}
