/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import junit.framework.TestCase;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests static AES crypto provider constants and methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-27
 */
public class AESCryptoTest  {


	@Test
	public void testClassAlgorithmSupport() {

		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).hasSize(6);

		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A128KW);
		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A192KW);
		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A256KW);
		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A128GCMKW);
		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A192GCMKW);
		assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A256GCMKW);
	}

	@Test
	public void testClassEncryptionMethodSupport() {

		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).hasSize(8);

		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A128CBC_HS256);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A192CBC_HS384);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A256CBC_HS512);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A128GCM);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A192GCM);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A256GCM);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A128CBC_HS256_DEPRECATED);
		assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A256CBC_HS512_DEPRECATED);
	}
}
