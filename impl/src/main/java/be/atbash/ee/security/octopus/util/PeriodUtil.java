package be.atbash.ee.security.octopus.util;

import be.atbash.config.exception.ConfigurationException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PeriodUtil {

    private static final Pattern PERIOD_PATTERN = Pattern.compile("(\\d+)([smh])");

    private PeriodUtil() {
    }

    public static int defineSecondsInPeriod(String periodConfig) {
        if (periodConfig == null) {
            throw new ConfigurationException(String.format("Period configuration '%s' is not valid, see documentation", periodConfig));
        }
        Matcher matcher = PERIOD_PATTERN.matcher(periodConfig);
        if (!matcher.matches()) {
            throw new ConfigurationException(String.format("Period configuration '%s' is not valid, see documentation", periodConfig));
        }

        String timeUnit = matcher.group(2);
        int result = -1;
        if ("s".equals(timeUnit)) {
            result = Integer.parseInt(matcher.group(1));
        }
        if ("m".equals(timeUnit)) {
            result = Integer.parseInt(matcher.group(1)) * 60;
        }
        if ("h".equals(timeUnit)) {
            result = Integer.parseInt(matcher.group(1)) * 3600;
        }

        return result;
    }
}
