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
package be.atbash.ee.security.octopus.json;

import be.atbash.ee.security.octopus.json.testclasses.JacksonCollectionPojoClass;
import be.atbash.ee.security.octopus.json.testclasses.MainClass;
import be.atbash.ee.security.octopus.json.testclasses.ReferencedClass;
import be.atbash.ee.security.octopus.json.testclasses.SomePojo;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.assertj.core.api.Assertions;

public class AbstractJacksonJsonSerializerTest {

    @Test
    public void serialize() {

        MainClass data = new MainClass();
        data.setFieldA("stringValue");
        data.setAge(42);
        data.setCounter(1);
        data.setFlag(Boolean.TRUE);
        List<String> roles = new ArrayList<>();
        roles.add("role1");
        roles.add("role2");
        data.setRoles(roles);

        data.setParent("parentString");

        ReferencedClass referenced = new ReferencedClass();
        Set<String> set = new HashSet<>();
        set.add("value2");
        set.add("value1");
        referenced.setData(set);
        data.setReferencedClass(referenced);

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(data, new JWTParametersNone());

        Assertions.assertThat(json).isEqualTo("{\"field-a\":\"stringValue\",\"age\":42,\"counter\":1,\"flag\":1,\"roles\":[\"role1\",\"role2\"],\"reference\":{\"data\":[\"value2\",\"value1\"]},\"parent\":\"parentString\"}");

    }

    @Test
    public void collectionOfPojo() {
        JacksonCollectionPojoClass main = new JacksonCollectionPojoClass();

        List<SomePojo> pojos = new ArrayList<>();

        pojos.add(createPojo(1L, "name1"));
        pojos.add(createPojo(2L, "name2"));

        main.setPojos(pojos);
        main.setType("test");

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(main, new JWTParametersNone());

        Assertions.assertThat(json).isEqualTo("{\"type\":\"test\",\"pojo-arr\":[{\"pojo-id\":1,\"pojo-name\":\"name1\"},{\"pojo-id\":2,\"pojo-name\":\"name2\"}]}");

    }

    private SomePojo createPojo(long id, String name) {
        SomePojo somePojo = new SomePojo();
        somePojo.setId(id);
        somePojo.setName(name);
        return somePojo;
    }

}