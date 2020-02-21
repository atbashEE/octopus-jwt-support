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
package be.atbash.ee.security.octopus.json.testclasses;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class JacksonCollectionPojoClass {

    @JsonProperty
    private String type;

    @JsonProperty("pojo-arr")
    private List<SomePojo> pojos;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<SomePojo> getPojos() {
        return pojos;
    }

    public void setPojos(List<SomePojo> pojos) {
        this.pojos = pojos;
    }
}
