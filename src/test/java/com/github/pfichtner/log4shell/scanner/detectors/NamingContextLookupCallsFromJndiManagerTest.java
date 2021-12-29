package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class NamingContextLookupCallsFromJndiManagerTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithoutJndiLookups = log4jJars.versions( //
			"2.0-alpha1", //
			"2.0-alpha2", //

			"2.0-beta1", //
			"2.0-beta2", //
			"2.0-beta3", //
			"2.0-beta4", //
			"2.0-beta5", //
			"2.0-beta6", //
			"2.0-beta7", //
			"2.0-beta8", //
			"2.0-beta9", //

			"2.0-rc1", //
			"2.0-rc2", //

			"2.0", //
			"2.0.1", //
			"2.0.2", //

			/**
			 * Starting with 2.15. DirContext lookups are made
			 */
			"2.15.0", //
			"2.16.0", //
			"2.17.0", //
			"2.17.1" //

	);

	NamingContextLookupCallsFromJndiManager sut = new NamingContextLookupCallsFromJndiManager();

	@Test
	void log4j14HasJndiManagerWithContextLookups() throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		assertThat(getFormatted(detector.analyze(log4jJars.version("2.14.1").getAbsolutePath())))
				.singleElement(as(STRING)).startsWith(refTo("javax.naming.Context#lookup(java.lang.String)"));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class org.apache.logging.log4j.core.net.JndiManager", ref);
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutJndiLookups));
	}

}
