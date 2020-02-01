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
package be.atbash.ee.security.octopus.json;

import be.atbash.util.exception.AtbashUnexpectedException;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonValue;
import javax.json.bind.serializer.JsonbSerializer;
import javax.json.bind.serializer.SerializationContext;
import javax.json.stream.JsonGenerator;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;

public abstract class AbstractJacksonJsonSerializer<T> implements JsonbSerializer<T> {

    private static final String JACKSON_JSON_PROPERTY_ANNOTATION = "com.fasterxml.jackson.annotation.JsonProperty";

    @Override
    public void serialize(T obj, JsonGenerator jsonGenerator, SerializationContext ctx) {
        jsonGenerator = jsonGenerator.writeStartObject();

        generateJSON(jsonGenerator, obj);

        jsonGenerator.writeEnd();
    }

    private void generateJSON(JsonGenerator jsonGenerator, Object data) {
        Class<?> currentClass = data.getClass();
        while (!currentClass.equals(Object.class)) {

            Field[] fields = currentClass.getDeclaredFields();
            for (Field field : fields) {

                boolean hasAnnotation = hasAnnotationValue(field);
                if (hasAnnotation) {
                    writeJsonField(jsonGenerator, field, data);
                }
            }
            currentClass = currentClass.getSuperclass();
        }
    }

    private void writeJsonField(JsonGenerator jsonGenerator, Field field, Object data) {
        Object fieldValue;
        try {
            field.setAccessible(true);
            fieldValue = field.get(data);
        } catch (IllegalAccessException e) {
           throw new AtbashUnexpectedException(e);
        }
        if (fieldValue == null) {
            return;  // don't write empty fields.
        }

        for (Annotation annotation : field.getAnnotations()) {
            if (annotation.annotationType().getName().equals(JACKSON_JSON_PROPERTY_ANNOTATION)) {
                String propertyName;
                try {
                    propertyName = getPropertyName(annotation, field);
                    JsonValue value = null;
                    Class<?> type = field.getType();
                    if (type.equals(String.class)) {
                        value = Json.createValue((String) fieldValue);
                    }
                    if (type.equals(Integer.class) || type.equals(int.class)) {
                        value = Json.createValue((Integer) fieldValue);
                    }
                    if (type.equals(Long.class) || type.equals(long.class)) {
                        value = Json.createValue((Long) fieldValue);
                    }
                    if (type.equals(Double.class) || type.equals(double.class)) {
                        value = Json.createValue((Double) fieldValue);
                    }
                    if (type.equals(Boolean.class) || type.equals(boolean.class)) {
                        Boolean flag = (Boolean) fieldValue;
                        value = Json.createValue(flag ? 1 : 0);
                    }
                    if (Collection.class.isAssignableFrom(type)) {
                        // FIXME Collection of POJO
                        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                        Collection collection = (Collection) fieldValue;
                        collection.forEach(item -> arrayBuilder.add(item.toString()));
                        value = arrayBuilder.build();
                    }
                    if (value == null) {
                        jsonGenerator.writeStartObject(propertyName);
                        generateJSON(jsonGenerator, fieldValue);
                        jsonGenerator.writeEnd();
                    } else {
                        jsonGenerator.write(propertyName, value);
                    }

                } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }

            }
        }

    }

    private String getPropertyName(Annotation annotation, Field field) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        String propertyName = annotation.getClass().getMethod("value").invoke(annotation).toString();
        if (propertyName == null || propertyName.isEmpty()) {
            propertyName = field.getName();
        }
        return propertyName;
    }

    private boolean hasAnnotationValue(Field field) {
        boolean result = false;
        for (Annotation annotation : field.getAnnotations()) {
            if (annotation.annotationType().getName().equals(JACKSON_JSON_PROPERTY_ANNOTATION)) {
                result = true;
            }
        }
        return result;
    }
}
