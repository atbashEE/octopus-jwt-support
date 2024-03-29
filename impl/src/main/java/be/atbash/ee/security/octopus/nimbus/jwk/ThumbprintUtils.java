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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.util.JsonbUtil;

import javax.json.bind.Jsonb;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Thumbprint utilities.
 *
 * <p>See RFC 7638.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public final class ThumbprintUtils {


    private ThumbprintUtils() {
    }

    /**
     * Computes the SHA-256 thumbprint for the specified JWK.
     *
     * @param jwk The JWK. Must not be {@code null}.
     * @return The JWK thumbprint.
     */
    public static Base64URLValue compute(JWK jwk) {

        return compute("SHA-256", jwk);
    }


    /**
     * Computes the thumbprint for the specified JWK.
     *
     * @param hashAlg The hash algorithm. Must not be {@code null}.
     * @param jwk     The JWK. Must not be {@code null}.
     * @return The JWK thumbprint.
     */
    public static Base64URLValue compute(String hashAlg, JWK jwk) {

        LinkedHashMap<String, ?> orderedParams = jwk.getRequiredParams();

        return compute(hashAlg, orderedParams);
    }


    /**
     * Computes the thumbprint for the specified required JWK parameters.
     *
     * @param hashAlg The hash algorithm. Must not be {@code null}.
     * @param params  The required JWK parameters, alphanumerically sorted
     *                by parameter name and ready for JSON object
     *                serialisation. Must not be {@code null}.
     * @return The JWK thumbprint.
     */
    public static Base64URLValue compute(String hashAlg, LinkedHashMap<String, ?> params) {

        Jsonb jsonb = JsonbUtil.getJsonb();
        String json = jsonb.toJson(params);

        MessageDigest md;

        try {
            md = MessageDigest.getInstance(hashAlg);

        } catch (NoSuchAlgorithmException e) {

            throw new JOSEException("Couldn't compute JWK thumbprint: Unsupported hash algorithm: " + e.getMessage(), e);
        }

        md.update(json.getBytes(UTF_8));

        return Base64URLValue.encode(md.digest());
    }
}
