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
package be.atbash.ee.security.octopus.util;

import be.atbash.config.exception.ConfigurationException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

public class PeriodUtilTest {

    @Test
    public void defineSecondsInPeriod_sec() {

        Assertions.assertThat(PeriodUtil.defineSecondsInPeriod("3s")).isEqualTo(3);
    }

    @Test
    public void defineSecondsInPeriod_min() {

        Assertions.assertThat(PeriodUtil.defineSecondsInPeriod("7m")).isEqualTo(7 * 60);
    }

    @Test
    public void defineSecondsInPeriod_hour() {

        Assertions.assertThat(PeriodUtil.defineSecondsInPeriod("1h")).isEqualTo(3600);
    }

    @Test
    public void defineSecondsInPeriod_empty() {

        Assertions.assertThatThrownBy(() -> PeriodUtil.defineSecondsInPeriod(""))
                .isInstanceOf(ConfigurationException.class)
                .hasMessage("Period configuration '' is not valid, see documentation");
    }

    @Test
    public void defineSecondsInPeriod_null() {

        Assertions.assertThatThrownBy(() -> PeriodUtil.defineSecondsInPeriod(null))
                .isInstanceOf(ConfigurationException.class)
                .hasMessage("Period configuration 'null' is not valid, see documentation");

    }

    @Test
    public void defineSecondsInPeriod_mixed() {

        Assertions.assertThatThrownBy(() -> PeriodUtil.defineSecondsInPeriod("3m10s"))
                .isInstanceOf(ConfigurationException.class)
                .hasMessage("Period configuration '3m10s' is not valid, see documentation");

    }

}