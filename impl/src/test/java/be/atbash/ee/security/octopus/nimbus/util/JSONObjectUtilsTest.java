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


import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JSON object utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-05
 */
public class JSONObjectUtilsTest {

    @Test
    public void testParseTrailingWhiteSpace()
            throws Exception {

        assertThat(JSONObjectUtils.parse("{} ").size()).isEqualTo(0);
        assertThat(JSONObjectUtils.parse("{}\n").size()).isEqualTo(0);
        assertThat(JSONObjectUtils.parse("{}\r\n").size()).isEqualTo(0);
    }


    @Test
    public void testGetURI() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", "https://c2id.net");
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isEqualTo(URI.create("https://c2id.net"));
    }

    @Test
    public void testGetURI_null() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }

    @Test
    public void testGetURI_missing() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }


    @Test
    public void testGetStringList() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
        assertThat(JSONObjectUtils.getStringList(jsonObject, "key")).containsExactly("apple", "pear");
    }

    @Test
    public void testGetStringList_null() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isNull();
    }

    @Test
    public void testGetStringList_missing() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isNull();
    }

}
