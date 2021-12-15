package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerWithContextLookups;

class CheckForJndiManagerWithContextLookupsTest {

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
			"2.0.2" //

	);

	@Test
	void log4j14HasJndiManagerWithContextLookups() throws Exception {
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.14.1").getAbsolutePath());
		assertThat(detections.getDetections()).containsExactly(refTo("javax.naming.Context#lookup(java.lang.String)"));
	}

	@Test
	void log4j16HasJndiManagerWithDirContextLookups() throws Exception {
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(detections.getDetections())
				.containsExactly(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		CheckForJndiManagerWithContextLookups sut = new CheckForJndiManagerWithContextLookups();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutJndiLookups));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class org/apache/logging/log4j/core/net/JndiManager.class", ref);
	}

}
