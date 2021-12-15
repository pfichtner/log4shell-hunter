package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerWithContextLookups;

class CheckForJndiManagerWithContextLookupsTest {

	List<String> versionsWithoutJndiLookups = asList( //
			"log4j-core-2.0-alpha1.jar", //
			"log4j-core-2.0-alpha2.jar", //

			"log4j-core-2.0-beta1.jar", //
			"log4j-core-2.0-beta2.jar", //
			"log4j-core-2.0-beta3.jar", //
			"log4j-core-2.0-beta4.jar", //
			"log4j-core-2.0-beta5.jar", //
			"log4j-core-2.0-beta6.jar", //
			"log4j-core-2.0-beta7.jar", //
			"log4j-core-2.0-beta8.jar", //
			"log4j-core-2.0-beta9.jar", //

			"log4j-core-2.0-rc1.jar", //
			"log4j-core-2.0-rc2.jar", //

			"log4j-core-2.0.jar", //
			"log4j-core-2.0.1.jar", //
			"log4j-core-2.0.2.jar" //

	// fixed
//			"log4j-core-2.15.0.jar", //
//			"log4j-core-2.16.0.jar"
	);

	@Test
	void log4j14HasJndiManagerWithContextLookups() throws Exception {
		Log4jJars log4jJars = Log4jJars.getInstance();
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.14.1").getAbsolutePath());
		assertThat(detections.getDetections()).containsExactly(refTo("javax.naming.Context#lookup(java.lang.String)"));
	}

	@Test
	void log4j16HasJndiManagerWithDirContextLookups() throws Exception {
		Log4jJars log4jJars = Log4jJars.getInstance();
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(detections.getDetections())
				.containsExactly(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		Log4jJars log4jJars = Log4jJars.getInstance();
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutJndiLookups));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class org/apache/logging/log4j/core/net/JndiManager.class", ref);
	}

}
