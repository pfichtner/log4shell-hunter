package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class IsJndiEnabledPropertyAccessWithJdbcPrefixTest {

	IsJndiEnabledPropertyAccessWithJdbcPrefix sut = new IsJndiEnabledPropertyAccessWithJdbcPrefix();

	@Test
	void propertyAccessWasIntroducedLog4J2171(Log4jJars log4jJars) throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		assertThat(getFormatted(detector.analyze(log4jJars.version("2.17.1").getAbsolutePath())))
				.singleElement(as(STRING)).startsWith(
						"log4j2.enableJndiJdbc access found in class org.apache.logging.log4j.core.net.JndiManager");
	}

	@Test
	void canDetectAccess(Log4jJars log4jJars) throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.versionsHigherOrEqualTo("2.17.1"));
	}

}
