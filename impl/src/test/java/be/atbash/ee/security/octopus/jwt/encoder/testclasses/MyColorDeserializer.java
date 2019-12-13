package be.atbash.ee.security.octopus.jwt.encoder.testclasses;

import javax.json.JsonObject;
import javax.json.bind.serializer.DeserializationContext;
import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.stream.JsonParser;
import java.lang.reflect.Type;

public class MyColorDeserializer implements JsonbDeserializer<MyColor> {

    @Override
    public MyColor deserialize(JsonParser jsonParser, DeserializationContext ctx, Type rtType) {
        JsonObject jsonObject = jsonParser.getObject();
        String[] values = jsonObject.getString("value").split(",");

        return new MyColor(Integer.parseInt(values[0]), Integer.parseInt(values[1]), Integer.parseInt(values[2]));
    }
}
