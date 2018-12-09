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
package be.atbash.ee.security.octopus.keys.subview.model;

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

/**
 *
 */

public class AtbashKeyItem {

    private StringProperty kid = new SimpleStringProperty();
    private String keyType;
    private AsymmetricPart asymmetricPart;
    private BooleanProperty selected = new SimpleBooleanProperty(true);

    public StringProperty kidProperty() {
        return kid;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public AsymmetricPart getAsymmetricPart() {
        return asymmetricPart;
    }

    public void setAsymmetricPart(AsymmetricPart asymmetricPart) {
        this.asymmetricPart = asymmetricPart;
    }

    public BooleanProperty selectedProperty() {
        return selected;
    }

    public boolean isSelected() {
        return selected.getValue();
    }

    public String getAsymmetricText() {
        String result = "Symmetric";
        if (asymmetricPart != null) {
            switch (asymmetricPart) {

                case PUBLIC:
                    result = "Public";
                    break;
                case PRIVATE:
                    result = "Private";
                    break;
                default:
                    throw new IllegalArgumentException(String.format("AsymmetricPart not supported %s", asymmetricPart));
            }
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        AtbashKeyItem that = (AtbashKeyItem) o;

        if (!kid.equals(that.kid)) {
            return false;
        }
        return asymmetricPart == that.asymmetricPart;
    }

    @Override
    public int hashCode() {
        int result = kid.hashCode();
        result = 31 * result + (asymmetricPart != null ? asymmetricPart.hashCode() : 0);
        return result;
    }
}
