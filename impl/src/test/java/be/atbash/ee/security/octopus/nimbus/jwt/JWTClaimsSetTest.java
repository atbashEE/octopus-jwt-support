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
package be.atbash.ee.security.octopus.nimbus.jwt;

import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import jakarta.json.*;
import org.assertj.core.api.Assertions;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.Test;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.*;

class JWTClaimsSetTest {

    @Test
    void issuer() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("issuer")
                .build();

        Assertions.assertThat(claimsSet.getIssuer()).isEqualTo("issuer");
        Assertions.assertThat(claimsSet.getClaim("iss")).isEqualTo("issuer");
        Assertions.assertThat(claimsSet.getStringClaim("iss")).isEqualTo("issuer");

    }

    @Test
    void issuer_wrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("iss", 123L)
                .build();

        Assertions.assertThat(claimsSet.getIssuer()).isNull();

        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("iss")).isInstanceOf(ParseException.class)
                .hasMessage("The \"iss\" claim is not a String");
    }

    @Test
    void subject() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .build();

        Assertions.assertThat(claimsSet.getSubject()).isEqualTo("subject");
        Assertions.assertThat(claimsSet.getClaim("sub")).isEqualTo("subject");
        Assertions.assertThat(claimsSet.getStringClaim("sub")).isEqualTo("subject");

    }

    @Test
    void subject_wrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("sub", 123L)
                .build();

        Assertions.assertThat(claimsSet.getSubject()).isNull();

        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("sub")).isInstanceOf(ParseException.class)
                .hasMessage("The \"sub\" claim is not a String");


    }

    @Test
    void audience_asString() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("audience")
                .build();

        Assertions.assertThat(claimsSet.getAudience()).containsExactly("audience");
        Object aud = claimsSet.getClaim("aud");
        Assertions.assertThat(aud).isInstanceOf(List.class);
        Assertions.assertThat((List) aud).containsExactly("audience");

        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("aud")).isInstanceOf(ParseException.class)
                .hasMessage("The \"aud\" claim is not a String");

    }

    @Test
    void audience_asString_multiple() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("aud1,aud2")
                .build();

        Assertions.assertThat(claimsSet.getAudience()).containsExactly("aud1", "aud2");
        Object aud = claimsSet.getClaim("aud");
        Assertions.assertThat(aud).isInstanceOf(List.class);
        Assertions.assertThat((List) aud).containsExactly("aud1", "aud2");

        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("aud")).isInstanceOf(ParseException.class)
                .hasMessage("The \"aud\" claim is not a String");

    }

    @Test
    void audience_asString_custom() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("aud", "aud1 , aud2")
                .build();

        Assertions.assertThat(claimsSet.getAudience()).containsExactly("aud1", "aud2");
        Assertions.assertThat(claimsSet.getClaim("aud")).isEqualTo("aud1 , aud2");
        Assertions.assertThat(claimsSet.getStringClaim("aud")).isEqualTo("aud1 , aud2");

    }

    @Test
    void audience_asString_null() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience((String) null)
                .build();

        Assertions.assertThat(claimsSet.getAudience()).isEmpty();
        Assertions.assertThat(claimsSet.getClaim("aud")).isNull();
        Assertions.assertThat(claimsSet.getStringClaim("aud")).isNull();

    }

    @Test
    void audience_asList() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(Arrays.asList("aud1", "aud2"))
                .build();

        Assertions.assertThat(claimsSet.getAudience()).containsExactly("aud1", "aud2");
        Object aud = claimsSet.getClaim("aud");
        Assertions.assertThat(aud).isInstanceOf(List.class);
        Assertions.assertThat((List) aud).containsExactly("aud1", "aud2");
        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("aud")).isInstanceOf(ParseException.class)
                .hasMessage("The \"aud\" claim is not a String");

    }

    @Test
    void audience_wrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("aud", 123L)
                .build();

        Assertions.assertThat(claimsSet.getAudience()).isEmpty();

        Assertions.assertThatThrownBy(() -> {
                    claimsSet.getStringClaim("aud");
                }).isInstanceOf(ParseException.class)
                .hasMessage("The \"aud\" claim is not a String");


    }

    @Test
    void expirationTime() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(now)
                .build();

        Assertions.assertThat(claimsSet.getExpirationTime()).isEqualTo(now);
        Assertions.assertThat(claimsSet.getClaim("exp")).isEqualTo(now);
        // /1000 to remove the ms they are not kept within the JWT either.
        Assertions.assertThat(claimsSet.getLongClaim("exp")).isEqualTo(now.getTime() / 1000);

    }

    @Test
    void expirationTime_asDuration() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(Duration.of(30, ChronoUnit.SECONDS))
                .build();

        long timeDifference = claimsSet.getExpirationTime().getTime() - now.getTime();
        Assertions.assertThat(timeDifference).isCloseTo(30_000L,  Offset.offset(50L));
    }

    @Test
    void expirationTime_asDuration_negative() throws ParseException {

        Assertions.assertThatThrownBy( () ->
         new JWTClaimsSet.Builder()
                .expirationTime(Duration.of(-30, ChronoUnit.SECONDS))
        ).isInstanceOf(IllegalArgumentException.class).hasMessage("The specified time duration in the parameter can't be smaller then 0.");

    }

    @Test
    void expirationTime_wrongValue() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("exp", "JUnit")
                .build();

        Assertions.assertThat(claimsSet.getExpirationTime()).isNull();
    }

    @Test
    void notBeforeTime() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .notBeforeTime(now)
                .build();

        Assertions.assertThat(claimsSet.getNotBeforeTime()).isEqualTo(now);
        Assertions.assertThat(claimsSet.getClaim("nbf")).isEqualTo(now);
        // /1000 to remove the ms they are not kept within the JWT either.
        Assertions.assertThat(claimsSet.getLongClaim("nbf")).isEqualTo(now.getTime() / 1000);

    }

    @Test
    void notBeforeTime_wrongValue() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nbf", "JUnit")
                .build();

        Assertions.assertThat(claimsSet.getNotBeforeTime()).isNull();
    }

    @Test
    void issueTime() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issueTime(now)
                .build();

        Assertions.assertThat(claimsSet.getIssueTime()).isEqualTo(now);
        Assertions.assertThat(claimsSet.getClaim("iat")).isEqualTo(now);
        // /1000 to remove the ms they are not kept within the JWT either.
        Assertions.assertThat(claimsSet.getLongClaim("iat")).isEqualTo(now.getTime() / 1000);

    }

    @Test
    void issueTime_wrongValue() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("iat", "JUnit")
                .build();

        Assertions.assertThat(claimsSet.getIssueTime()).isNull();
    }

    @Test
    void id() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID("theId")
                .build();

        Assertions.assertThat(claimsSet.getJWTID()).isEqualTo("theId");
        Assertions.assertThat(claimsSet.getClaim("jti")).isEqualTo("theId");

    }


    @Test
    void id_wrongValue() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("jti", 123L)
                .build();

        Assertions.assertThat(claimsSet.getJWTID()).isNull();

        Assertions.assertThatThrownBy(() -> claimsSet.getStringClaim("jti")).isInstanceOf(ParseException.class)
                .hasMessage("The \"jti\" claim is not a String");

    }


    @Test
    void getLongClaim() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("longVal", 54321L)
                .build();

        Assertions.assertThat(claimsSet.getLongClaim("longVal")).isEqualTo(54321L);
    }

    @Test
    void getLongClaim_fromDouble() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("doubleVal", 123.45D)
                .build();

        Assertions.assertThat(claimsSet.getLongClaim("doubleVal")).isEqualTo(123L);
    }

    @Test
    void getLongClaim_fromDate() throws ParseException {
        DateFormat dfm = new SimpleDateFormat("dd/MM/yyyy");
        Date date = dfm.parse("01/01/2022");

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issueTime(date)
                .build();

        Assertions.assertThat(claimsSet.getLongClaim("iat")).isEqualTo(1640991600L);
    }

    @Test
    void getStringArrayClaim() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("array", Arrays.asList("item1", "item2", "item3"))
                .build();

        Assertions.assertThat(claimsSet.getStringArrayClaim("array")).containsExactly("item1", "item2", "item3");
    }

    @Test
    void getStringArrayClaim_withArray() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("array", new String[]{"item1", "item2", "item3"})
                .build();

        Assertions.assertThat(claimsSet.getStringArrayClaim("array")).containsExactly("item1", "item2", "item3");
    }

    @Test
    void getStringArrayClaim_withArrayOfNumbers() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("array", new Long[]{123L, 456L, 789L})
                .build();

        Assertions.assertThat(claimsSet.getStringArrayClaim("array")).containsExactly("123", "456", "789");
    }

    @Test
    void getStringArrayClaim_withJsonArray() throws ParseException {
        Map<String, ?> config = new HashMap<>();
        JsonBuilderFactory factory = Json.createBuilderFactory(config);
        JsonArray value = factory.createArrayBuilder()
                .add("item1")
                .add("item2")
                .add("item3")
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("array", value)
                .build();

        Assertions.assertThat(claimsSet.getStringArrayClaim("array")).containsExactly("item1", "item2", "item3");
    }

    @Test
    void getStringArrayClaim_WrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("array", "item")
                .build();

        Assertions.assertThatThrownBy(() -> claimsSet.getStringArrayClaim("array")).isInstanceOf(ParseException.class)
                .hasMessage("The \"array\" claim is not a list / JSON array");

    }

    @Test
    void getBooleanClaim() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("bool", Boolean.TRUE)
                .build();

        Assertions.assertThat(claimsSet.getBooleanClaim("bool")).isTrue();
    }

    @Test
    void getBooleanClaim_forString() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("bool", "tRuE")
                .build();

        Assertions.assertThat(claimsSet.getBooleanClaim("bool")).isTrue();
    }

    @Test
    void getBooleanClaim_wrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("bool", 1234L)
                .build();

        Assertions.assertThatThrownBy(() -> claimsSet.getBooleanClaim("bool")).isInstanceOf(ParseException.class)
                .hasMessage("The \"bool\" claim is not a Boolean");

    }

    @Test
    void getIntegerClaim() throws ParseException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("intValue", 1234)
                .build();

        Assertions.assertThat(claimsSet.getIntegerClaim("intValue")).isEqualTo(1234);
    }

    @Test
    void getIntegerClaim_fromLong() throws ParseException {
        // Since it checks on Number
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("intValue", 6543L)
                .build();

        Assertions.assertThat(claimsSet.getIntegerClaim("intValue")).isEqualTo(6543);
    }

    @Test
    void getIntegerClaim_wrongValue() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("intValue", "JUnit")
                .build();

        Assertions.assertThatThrownBy(() -> claimsSet.getIntegerClaim("intValue")).isInstanceOf(ParseException.class)
                .hasMessage("The \"intValue\" claim is not an Integer");

    }

    @Test
    void dateClaim() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("now", now)
                .build();

        // Custom date claims don't have the seconds usage like exp, iat, ..
        Assertions.assertThat(claimsSet.getDateClaim("now")).isEqualTo(now);

    }

    @Test
    void dateClaim_asNumber() throws ParseException {
        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("now", now.getTime() / 1000)
                .build();

        LocalDateTime localDateTime = DateUtils.asLocalDateTime(now);
        Date truncatedNow = truncatedDate(localDateTime);

        // But a number that is interpreted as date is using the JWT seconds rule.
        Assertions.assertThat(claimsSet.getDateClaim("now")).isEqualTo(truncatedNow);

    }

    private Date truncatedDate(LocalDateTime localDateTime) {
        LocalDateTime temp = localDateTime.truncatedTo(ChronoUnit.SECONDS);
        return DateUtils.asDate(temp);
    }


    @Test
    void dateClaim_WrongValue() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("now", "JUnit")
                .build();

        Assertions.assertThatThrownBy(() -> claimsSet.getDateClaim("now")).isInstanceOf(ParseException.class)
                .hasMessage("The \"now\" claim is not a Date");
    }

    @Test
    void getJSONObjectClaim() throws ParseException {
        Map<String, ?> config = new HashMap<>();
        JsonBuilderFactory factory = Json.createBuilderFactory(config);
        JsonObject value = factory.createObjectBuilder()
                .add("key", "value")
                .add("sub", factory.createObjectBuilder()
                        .add("project", "Atbash")
                        .build())
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("obj", value)
                .build();

        Assertions.assertThat(claimsSet.getJSONObjectClaim("obj")).isEqualTo(value);
    }

    @Test
    void getJSONObjectClaim_asMap() throws ParseException {

        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("obj", map)
                .build();

        Map<String, ?> config = new HashMap<>();
        JsonBuilderFactory factory = Json.createBuilderFactory(config);
        JsonObject value = factory.createObjectBuilder()
                .add("key", "value")
                .build();


        Assertions.assertThat(claimsSet.getJSONObjectClaim("obj")).isEqualTo(value);
    }

    @Test
    void toJsonObject() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime exp = now.plusHours(24);
        LocalDateTime notBefore = now.plusHours(1);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("issuer")
                .subject("subject")
                .audience("audience")
                .jwtID("id")
                .issueTime(asDate(now))
                .notBeforeTime(asDate(notBefore))
                .expirationTime(asDate(exp))
                .claim("custom", "JUnit")
                .build();

        JsonObject jsonObject = claimsSet.toJSONObject();
        Assertions.assertThat(jsonObject.keySet()).hasSize(8);

        Assertions.assertThat(jsonObject.getString("iss")).isEqualTo("issuer");
        Assertions.assertThat(jsonObject.getString("sub")).isEqualTo("subject");
        Assertions.assertThat(jsonObject.getString("aud")).isEqualTo("audience");
        Assertions.assertThat(jsonObject.getString("jti")).isEqualTo("id");

        testDateValue(jsonObject.get("iat"), now);
        testDateValue(jsonObject.get("nbf"), notBefore);
        testDateValue(jsonObject.get("exp"), exp);

        Assertions.assertThat(jsonObject.getString("custom")).isEqualTo("JUnit");

    }

    private void testDateValue(JsonValue jsonValue, LocalDateTime dateValue) {
        Assertions.assertThat(jsonValue.getValueType()).isEqualTo(JsonValue.ValueType.NUMBER);
        Assertions.assertThat(jsonValue.toString()).isEqualTo(asDateValueInJson(dateValue));
    }

    private String asDateValueInJson(LocalDateTime localDateTime) {
        return String.valueOf(asDate(localDateTime).getTime() / 1000);
    }

    private long asDateValue(LocalDateTime localDateTime) {
        return asDate(localDateTime).getTime() / 1000;
    }

    private Date asDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    @Test
    void parse() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime exp = now.plusHours(24);
        LocalDateTime notBefore = now.plusHours(1);

        Map<String, ?> config = new HashMap<>();
        JsonBuilderFactory factory = Json.createBuilderFactory(config);
        Map<String, Object> data = new HashMap<>();
        data.put("iss", "issuer");
        data.put("sub", "subject");
        data.put("aud", "aud1,aud2");
        data.put("jti", "theId");

        data.put("iat", asDateValue(now));
        data.put("exp", asDateValue(exp));
        data.put("nbf", asDateValue(notBefore));
        data.put("custom", "JUnit");

        JsonObject jsonObject = factory.createObjectBuilder(data).build();

        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

        Assertions.assertThat(claimsSet.getIssuer()).isEqualTo("issuer");
        Assertions.assertThat(claimsSet.getSubject()).isEqualTo("subject");
        Assertions.assertThat(claimsSet.getAudience()).containsExactly("aud1", "aud2");
        Assertions.assertThat(claimsSet.getJWTID()).isEqualTo("theId");
        Assertions.assertThat(claimsSet.getIssueTime()).isEqualTo(truncatedDate(now));
        Assertions.assertThat(claimsSet.getNotBeforeTime()).isEqualTo(truncatedDate(notBefore));
        Assertions.assertThat(claimsSet.getExpirationTime()).isEqualTo(truncatedDate(exp));



    }

}