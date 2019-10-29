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
package be.atbash.ee.security.octopus.json.testclasses;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class MainClass extends ParentClass {

    @JsonProperty("field-a")
    private String fieldA;

    @JsonProperty
    private int age;

    @JsonProperty
    private long counter;

    @JsonProperty
    private Boolean flag;

    @JsonProperty
    private List<String> roles;

    @JsonProperty("reference")
    private ReferencedClass referencedClass;

    public String getFieldA() {
        return fieldA;
    }

    public void setFieldA(String fieldA) {
        this.fieldA = fieldA;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public Boolean getFlag() {
        return flag;
    }

    public void setFlag(Boolean flag) {
        this.flag = flag;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public ReferencedClass getReferencedClass() {
        return referencedClass;
    }

    public void setReferencedClass(ReferencedClass referencedClass) {
        this.referencedClass = referencedClass;
    }
}
