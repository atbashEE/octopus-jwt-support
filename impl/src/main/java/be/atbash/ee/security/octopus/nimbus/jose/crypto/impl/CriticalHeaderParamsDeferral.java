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


import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;

import java.util.Collections;
import java.util.Set;


/**
 * Critical ({@code crit}) header parameters deferral policy.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class CriticalHeaderParamsDeferral {

    /**
     * The names of the deferred critical headers.
     */
    private Set<String> deferredParams = Collections.emptySet();


    /**
     * Returns the names of the critical ({@code crit}) header parameters
     * that are understood and processed.
     *
     * @return immutable set with 'b64'.
     */
    public Set<String> getProcessedCriticalHeaderParams() {

        return Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD);
    }


    /**
     * Returns the names of the critical ({@code crit}) header parameters
     * that are deferred to the application for processing.
     *
     * @return The names of the critical header parameters that are
     * deferred to the application for processing, as an
     * unmodifiable set, empty set if none.
     */
    public Set<String> getDeferredCriticalHeaderParams() {

        return Collections.unmodifiableSet(deferredParams);
    }


    /**
     * Sets the names of the critical ({@code crit}) header parameters
     * that are deferred to the application for processing.
     *
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public void setDeferredCriticalHeaderParams(Set<String> defCritHeaders) {

        if (defCritHeaders == null) {
            deferredParams = Collections.emptySet();
        } else {
            deferredParams = defCritHeaders;
        }
    }


    /**
     * Returns {@code true} if the specified header passes the critical
     * parameters check.
     *
     * @param header The JWS or JWE header to check. Must not be
     *               {@code null}.
     * @return {@code true} if the header passes, {@code false} if the
     * header contains one or more critical header parameters which
     * are not marked for deferral to the application.
     */
    public boolean headerPasses(Header header) {

        if (header.getCriticalParams() == null) {
            return true; // ok
        }

        for (String critParam : header.getCriticalParams()) {
            if (getProcessedCriticalHeaderParams().contains(critParam)) {
                continue;
            }
            if (getDeferredCriticalHeaderParams().contains(critParam)) {
                continue;
            }
            return false;
        }
        return true;
    }


    /**
     * Throws a JOSE exception if the specified JWE header doesn't pass the
     * critical header parameters check.
     *
     * @param header The JWE header to check. Must not be {@code null}.
     */
    public void ensureHeaderPasses(JWEHeader header) {

        if (!headerPasses(header)) {
            throw new JOSEException("Unsupported critical header parameter(s)");
        }
    }
}
