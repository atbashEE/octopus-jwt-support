/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jose;


/**
 * Key length exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 205-06-29
 */
public class KeyLengthException extends KeyException {


    /**
     * The expected key length.
     */
    private final int expectedLength;


    /**
     * The algorithm.
     */
    private final Algorithm alg;


    /**
     * Creates a new key length exception.
     *
     * @param message The exception message.
     */
    public KeyLengthException(String message) {

        super(message);
        expectedLength = 0;
        alg = null;
    }


    /**
     * Creates a new key length exception.
     *
     * @param alg The JOSE algorithm, {@code null} if not specified.
     */
    public KeyLengthException(Algorithm alg) {

        this(0, alg);
    }


    /**
     * Creates a new key length exception.
     *
     * @param expectedLength The expected key length in bits, zero if not
     *                       specified.
     * @param alg            The JOSE algorithm, {@code null} if not
     *                       specified.
     */
    public KeyLengthException(int expectedLength, Algorithm alg) {

        super((
                (expectedLength > 0) ? "The expected key length is " + expectedLength + " bits" : "Unexpected key length") +
                ((alg != null) ? " (for " + alg + " algorithm)" : "")
        );

        this.expectedLength = expectedLength;
        this.alg = alg;
    }


    /**
     * Returns the expected key length.
     *
     * @return The expected key length in bits, zero if not specified.
     */
    public int getExpectedKeyLength() {

        return expectedLength;
    }


    /**
     * Returns the algorithm.
     *
     * @return The JOSE algorithm, {@code null} if not specified.
     */
    public Algorithm getAlgorithm() {

        return alg;
    }
}
