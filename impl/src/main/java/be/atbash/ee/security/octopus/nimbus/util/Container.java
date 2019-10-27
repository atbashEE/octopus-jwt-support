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
package be.atbash.ee.security.octopus.nimbus.util;


/**
 * Generic container of items of any type.
 *
 * <p>This class is not thread-safe, if thread safety is required it should be
 * done externally to the class.
 *
 * <p>The author believes he borrowed the idea for such a class many years ago
 * from a man called Boris Karadjov.
 *
 * @param <T> the type of the item in this container.
 * @author Dimitar A. Stoikov
 * @version 2016-10-13
 */
public class Container<T> {


    /**
     * The item.
     */
    private T item;


    /**
     * Creates a new container with no item.
     */
    public Container() {
    }


    /**
     * Creates a new container with the specified item.
     *
     * @param item The item, may be {@code null}.
     */
    public Container(T item) {
        this.item = item;
    }


    /**
     * Gets the contained item.
     *
     * @return The item, {@code null} if none.
     */
    public T get() {
        return item;
    }


    /**
     * Sets the contained item.
     *
     * @param item The item, may be {@code null}.
     */
    public void set(T item) {
        this.item = item;
    }
}