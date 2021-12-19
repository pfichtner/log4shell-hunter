package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.CVEDetector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

public class JndiLookupConstructorWithISExceptionTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	JndiLookupConstructorWithISException sut = new JndiLookupConstructorWithISException();

	@Test
	void throwingISEinJndiLookupConstructorWasIntroducedWIthLog4J217() throws Exception {
		CVEDetector detector = new CVEDetector(sut);
		assertThat(getFormatted(detector.analyze(log4jJars.version("2.17.0").getAbsolutePath())))
				.containsExactly("JNDI must be enabled by setting log4j2.enableJndiLookup=true access "
						+ "found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class");
	}

	@Test
	void canDetectAccess() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.versions("2.17.0").toArray(new File[0]));
	}

}
