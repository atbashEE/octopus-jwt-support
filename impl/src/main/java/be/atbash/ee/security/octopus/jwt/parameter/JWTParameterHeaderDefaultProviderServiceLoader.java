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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.util.ordered.OrderComparator;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

final class JWTParameterHeaderDefaultProviderServiceLoader {

    private static JWTParameterHeaderDefaultProviderServiceLoader INSTANCE;

    private final List<JWTParameterHeaderDefaultProvider> defaultProviders;

    private JWTParameterHeaderDefaultProviderServiceLoader() {
        defaultProviders = new ArrayList<>();
        ServiceLoader<JWTParameterHeaderDefaultProvider> providers = ServiceLoader.load(JWTParameterHeaderDefaultProvider.class);

        for (JWTParameterHeaderDefaultProvider provider : providers) {
            defaultProviders.add(provider);
        }
        defaultProviders.sort(new OrderComparator());
    }

    static synchronized List<JWTParameterHeaderDefaultProvider> getDefaultProviders() {
        // Synchronize methods are not so bad for performance anymore and since only 1 synchronized static there are no side effects
        if (INSTANCE == null) {
            INSTANCE = new JWTParameterHeaderDefaultProviderServiceLoader();
        }
        return INSTANCE.defaultProviders;
    }

}
