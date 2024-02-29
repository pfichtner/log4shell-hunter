package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;

import java.io.File;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

public class IsJndiEnabledPropertyAccessWithJdbcPrefixTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	IsJndiEnabledPropertyAccessWithJdbcPrefix sut = new IsJndiEnabledPropertyAccessWithJdbcPrefix();

	@Test
	void propertyAccessWasIntroducedLog4J2171() throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		assertThat(getFormatted(detector.analyze(log4jJars.version("2.17.1").getAbsolutePath())))
				.singleElement(as(STRING)).startsWith(
						"log4j2.enableJndiJdbc access found in class org.apache.logging.log4j.core.net.JndiManager");
	}

	@Test
	void canDetectAccess() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut))).containsOnlyKeys(log4jJars.versions("2.17.1", "2.17.2",
				"2.18.0", "2.19.0", "2.20.0", "2.21.0", "2.21.1", "2.22.0", "2.22.1", "2.23.0"

		).toArray(File[]::new));
	}

}
