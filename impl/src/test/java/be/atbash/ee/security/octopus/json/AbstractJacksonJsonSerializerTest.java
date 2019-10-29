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
package be.atbash.ee.security.octopus.json;

import be.atbash.ee.security.octopus.json.testclasses.MainClass;
import be.atbash.ee.security.octopus.json.testclasses.ReferencedClass;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

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

        assertThat(json).isEqualTo("{\"field-a\":\"stringValue\",\"age\":42,\"counter\":1,\"flag\":1,\"roles\":[\"role1\",\"role2\"],\"reference\":{\"data\":[\"value2\",\"value1\"]},\"parent\":\"parentString\"}");

    }

}