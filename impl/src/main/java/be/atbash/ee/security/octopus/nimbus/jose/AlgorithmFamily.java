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
package be.atbash.ee.security.octopus.nimbus.jose;


import java.util.Collection;
import java.util.LinkedHashSet;


/**
 * Algorithm family.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class AlgorithmFamily<T extends Algorithm> extends LinkedHashSet<T> {


    private static final long serialVersionUID = 1L;


    /**
     * Creates a new algorithm family.
     *
     * @param algs The algorithms of the family. Must not be {@code null}.
     */
    public AlgorithmFamily(T... algs) {
        for (T alg : algs) {
            super.add(alg);
        }
    }


    @Override
    public boolean add(T alg) {
        throw new UnsupportedOperationException();
    }


    @Override
    public boolean addAll(Collection<? extends T> algs) {
        throw new UnsupportedOperationException();
    }


    @Override
    public boolean remove(Object o) {
        throw new UnsupportedOperationException();
    }


    @Override
    public boolean removeAll(Collection<?> c) {
        throw new UnsupportedOperationException();
    }


    @Override
    public boolean retainAll(Collection<?> c) {
        throw new UnsupportedOperationException();
    }
}
