/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys.reader;

public interface KeyResourceTypeProvider {

    /**
     * Determine the KeyResourceType based on the suffix of the path name. For an URL based resource the suffix must also be in the same format.
     * @param path Location of the resource
     * @return KeyResourceType or null when suffix doesn't match.
     */
    KeyResourceType determineKeyResourceType(String path);
}
