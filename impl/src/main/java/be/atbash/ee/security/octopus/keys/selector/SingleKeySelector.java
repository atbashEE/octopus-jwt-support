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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.AtbashKey;

import javax.enterprise.inject.Vetoed;
import java.security.Key;

/**
 * Key Selector usable in some special Java SE cases where we only want to supply the encoder/decoder a single specific Key.
 */
@Vetoed // parent class is a CDI bean and otherwise this class would gives issues in CDI injection.
public class SingleKeySelector extends KeySelector {

    private AtbashKey theKey;

    public SingleKeySelector(AtbashKey theKey) {
        this.theKey = theKey;
    }

    @Override
    public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
        return (T) theKey.getKey();
    }

    @Override
    public AtbashKey selectAtbashKey(SelectorCriteria selectorCriteria) {
        return theKey;
    }
}
