package be.atbash.ee.security.octopus.jwt.encoder.testclasses;

import javax.json.bind.serializer.JsonbSerializer;
import javax.json.bind.serializer.SerializationContext;
import javax.json.stream.JsonGenerator;

public class MyColorSerializer implements JsonbSerializer<MyColor> {
    @Override
    public void serialize(MyColor myColor, JsonGenerator jsonGenerator, SerializationContext ctx) {
        String content = String.valueOf(myColor.getR()) + ',' + myColor.getG() + "," + myColor.getB();
        jsonGenerator.writeStartObject().writeKey("value").write(content).writeEnd();
    }
}
