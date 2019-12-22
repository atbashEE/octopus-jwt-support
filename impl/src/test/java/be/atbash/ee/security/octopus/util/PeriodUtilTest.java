package be.atbash.ee.security.octopus.util;

import be.atbash.config.exception.ConfigurationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PeriodUtilTest {

    @Test
    public void defineSecondsInPeriod_sec() {

        assertThat(PeriodUtil.defineSecondsInPeriod("3s")).isEqualTo(3);
    }

    @Test
    public void defineSecondsInPeriod_min() {

        assertThat(PeriodUtil.defineSecondsInPeriod("7m")).isEqualTo(7 * 60);
    }

    @Test
    public void defineSecondsInPeriod_hour() {

        assertThat(PeriodUtil.defineSecondsInPeriod("1h")).isEqualTo(3600);
    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_empty() {

        PeriodUtil.defineSecondsInPeriod("");

    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_null() {

        PeriodUtil.defineSecondsInPeriod(null);

    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_mixed() {

        PeriodUtil.defineSecondsInPeriod("3m10s");

    }

}