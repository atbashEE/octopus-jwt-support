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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;


import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.CommonJWTHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.slf4j.MDC;

import java.util.Date;


/**
 * {@link JWTVerifier JWT claims verifier} implementation. This class
 * is thread-safe.
 *
 * <p>Performs the following checks:
 *
 * <ol>
 *     <li>If an expiration time (exp) claim is present, makes sure it is ahead
 *         of the current time, else the JWT claims set is rejected.
 *     <li>If a not-before-time (nbf) claim is present, makes sure it is
 *         before the current time, else the JWT claims set is rejected.
 * </ol>
 *
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class DefaultJWTClaimsVerifier implements JWTVerifier {

    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private final int maxClockSkew;

    /**
     * Creates a new JWT claims verifier. Will check the expiration ("exp")
     * and not-before ("nbf") times if present.
     */
    public DefaultJWTClaimsVerifier() {

        maxClockSkew = JwtSupportConfiguration.getInstance().getClockSkewSeconds();
    }

    @Override
    public boolean verify(CommonJWTHeader header, JWTClaimsSet claimsSet) {

        // Check time window
        Date now = new Date();

        Date exp = claimsSet.getExpirationTime();
        if (exp != null) {

            if (!DateUtils.isAfter(exp, now, maxClockSkew)) {

                // These messages are in function of JWT validation by Atbash Runtime so have slightly narrow meaning of the provided parameters.
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format("The token was expired (exp = %s)", exp));
                return false;
            }
        }

        Date nbf = claimsSet.getNotBeforeTime();
        if (nbf != null) {

            if (!DateUtils.isBefore(nbf, now, maxClockSkew)) {
                // These messages are in function of JWT validation by Atbash Runtime so have slightly narrow meaning of the provided parameters.
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format("The token should not be used (nbf = %s)", nbf));
                return false;
            }
        }

        if (header instanceof JWSHeader && !((JWSHeader) header).isBase64URLEncodePayload()) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The token has a payload that is not encoded (b64=false)");
            return false;

        }
        return true;
    }
}
