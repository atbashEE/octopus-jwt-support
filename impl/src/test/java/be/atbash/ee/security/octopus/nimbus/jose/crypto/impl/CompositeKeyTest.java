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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.assertj.core.api.Assertions;


/**
 * Tests composite MAC + AES key extraction. Test cases from 
 * <a href="http://tools.ietf.org/html/rfc7518#appendix-B">Appendix B</a>
 * <p>
 * Based on code by  Vladimir Dzhuvinov
 */
public class CompositeKeyTest  {


	private static final byte[] K_256 = 
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f  };


	private static final byte[] MAC_KEY_128 = 
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f  };


	private static final byte[] ENC_KEY_128 =
		{ (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f  };


	private static final byte[] K_384 =
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
		  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
		  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
		  (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
		  (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b, (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f };


	private static final byte[] MAC_KEY_192 =
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
		  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17 };

	private static final byte[] ENC_KEY_192 =
		{ (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
		  (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
		  (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b, (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f };

	private static final byte[] K_512 = 
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
                  (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27, 
                  (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b, (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f,
                  (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, 
                  (byte)0x38, (byte)0x39, (byte)0x3a, (byte)0x3b, (byte)0x3c, (byte)0x3d, (byte)0x3e, (byte)0x3f  };


	private static final byte[] MAC_KEY_256 = 
		{ (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
		  (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                  (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                  (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f  };


	private static final byte[] ENC_KEY_256 =
		{ (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27, 
                  (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b, (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f,
                  (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, 
                  (byte)0x38, (byte)0x39, (byte)0x3a, (byte)0x3b, (byte)0x3c, (byte)0x3d, (byte)0x3e, (byte)0x3f  };


	@Test
	public void testExample256() {

		SecretKey inputKey = new SecretKeySpec(K_256, "AES");

		CompositeKey compositeKey = new CompositeKey(inputKey);

		Assertions.assertThat(compositeKey.getInputKey().getEncoded()).isEqualTo(K_256);

		Assertions.assertThat(compositeKey.getMACKey().getEncoded()).isEqualTo(MAC_KEY_128);
		Assertions.assertThat(compositeKey.getMACKey().getAlgorithm()).isEqualTo("HMACSHA256");
		Assertions.assertThat(compositeKey.getTruncatedMACByteLength()).isEqualTo(16);

		Assertions.assertThat(compositeKey.getAESKey().getEncoded()).isEqualTo(ENC_KEY_128);
		Assertions.assertThat(compositeKey.getAESKey().getAlgorithm()).isEqualTo("AES");
	}


	@Test
	public void testExample384() {

		SecretKey inputKey = new SecretKeySpec(K_384, "AES");

		CompositeKey compositeKey = new CompositeKey(inputKey);

		Assertions.assertThat(compositeKey.getInputKey().getEncoded()).isEqualTo(K_384);

		Assertions.assertThat(compositeKey.getMACKey().getEncoded()).isEqualTo(MAC_KEY_192);
		Assertions.assertThat(compositeKey.getMACKey().getAlgorithm()).isEqualTo("HMACSHA384");
		Assertions.assertThat(compositeKey.getTruncatedMACByteLength()).isEqualTo(24);

		Assertions.assertThat(compositeKey.getAESKey().getEncoded()).isEqualTo(ENC_KEY_192);
		Assertions.assertThat(compositeKey.getAESKey().getAlgorithm()).isEqualTo("AES");
	}

	@Test
	public void testExample512() {

		SecretKey inputKey = new SecretKeySpec(K_512, "AES");

		CompositeKey compositeKey = new CompositeKey(inputKey);

		Assertions.assertThat(compositeKey.getInputKey().getEncoded()).isEqualTo(K_512);

		Assertions.assertThat(compositeKey.getMACKey().getEncoded()).isEqualTo(MAC_KEY_256);
		Assertions.assertThat(compositeKey.getMACKey().getAlgorithm()).isEqualTo("HMACSHA512");
		Assertions.assertThat(compositeKey.getTruncatedMACByteLength()).isEqualTo(32);

		Assertions.assertThat(compositeKey.getAESKey().getEncoded()).isEqualTo(ENC_KEY_256);
		Assertions.assertThat(compositeKey.getAESKey().getAlgorithm()).isEqualTo("AES");
	}

	@Test
	public void testUnsupportedInputKeyLength() {

		SecretKey inputKey = new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}, "AES");

		Assertions.assertThatThrownBy(
				() -> new CompositeKey(inputKey))
				.isInstanceOf(KeyLengthException.class);
	}
}