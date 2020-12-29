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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import jakarta.json.JsonObject;
import java.text.ParseException;


/**
 * Parser for unsecured (plain), signed and encrypted JSON Web Tokens (JWTs).
 *
 * Based on code by Vladimir Dzhuvinov and Junya Hayashi
 */
public final class JWTParser {


	/**
	 * Parses an unsecured (plain), signed or encrypted JSON Web Token
	 * (JWT) from the specified string in compact format.
	 *
	 * @param data The string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link PlainJWT}, {@link SignedJWT} or
	 *         {@link EncryptedJWT} instance.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        unsecured, signed or encrypted JWT.
	 */
	public static JWT parse(String data)
		throws ParseException {

		 int firstDotPos = data.indexOf(".");
		
		if (firstDotPos == -1) {
			throw new ParseException("Invalid JWT serialization: Missing dot delimiter(s)", 0);
		}

		Base64URLValue header = new Base64URLValue(data.substring(0, firstDotPos));
		
		JsonObject jsonObject;

		try {
			jsonObject = JSONObjectUtils.parse(header.decodeToString());

		} catch (ParseException e) {

			throw new ParseException("Invalid unsecured/JWS/JWE header: " + e.getMessage(), 0);
		}

		Algorithm alg = Algorithm.parseAlgorithm(jsonObject);

		if (alg.equals(Algorithm.NONE)) {
			return PlainJWT.parse(data);
		} else if (alg instanceof JWSAlgorithm) {
			return SignedJWT.parse(data);
		} else if (alg instanceof JWEAlgorithm) {
			return EncryptedJWT.parse(data);
		} else {
			throw new AssertionError("Unexpected algorithm type: " + alg);
		}
	}


	/**
	 * Prevents instantiation.
	 */
	private JWTParser() {

	}
}
