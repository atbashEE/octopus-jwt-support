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


import java.io.Serializable;


/**
 * The base class for algorithm names, with optional implementation
 * requirement. This class is immutable.
 *
 * <p>Includes constants for the following standard algorithm names:
 *
 * <ul>
 *     <li>{@link #NONE none}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2013-03-27
 */
public class Algorithm implements Serializable {


    private static final long serialVersionUID = 1L;


    /**
     * No algorithm (unsecured JOSE object without signature / encryption).
     */
    public static final Algorithm NONE = new Algorithm("none");


    /**
     * The algorithm name.
     */
    private String name;

    /**
     * Creates a new JOSE algorithm name.
     *
     * @param name The algorithm name. Must not be {@code null}.
     */
    public Algorithm(String name) {

        if (name == null) {

            throw new IllegalArgumentException("The algorithm name must not be null");
        }

        this.name = name;

    }


    /**
     * Gets the name of this algorithm.
     *
     * @return The algorithm name.
     */
    public String getName() {

        return name;
    }

    /**
     * Overrides {@code Object.hashCode()}.
     *
     * @return The object hash code.
     */
    @Override
    public int hashCode() {

        return name.hashCode();
    }


    /**
     * Overrides {@code Object.equals()}.
     *
     * @param object The object to compare to.
     * @return {@code true} if the objects have the same value, otherwise
     * {@code false}.
     */
    @Override
    public boolean equals(Object object) {

        return object instanceof Algorithm &&
                this.toString().equals(object.toString());
    }


    /**
     * Returns the string representation of this algorithm.
     *
     * @return The string representation.
     * @see #getName
     */
    @Override
    public String toString() {

        return name;
    }


}
