package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerWithDirContextLookups;

class CheckForJndiManagerWithDirContextLookupsTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	/**
	 * DirContext lookups have been introduced with version 2.15.0
	 */
	List<File> versionsWithoutDirContextLookups = log4jJars.versions( //
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
			"2.1", //
			"2.2", //
			"2.3", //
			"2.4", //
			"2.4.1", //
			"2.5", //
			"2.6", //
			"2.6.1", //
			"2.6.2", //
			"2.7", //
			"2.8", //
			"2.8.1", //
			"2.8.2", //
			"2.9.0", //
			"2.9.1", //
			"2.10.0", //
			"2.11.0", //
			"2.11.1", //
			"2.11.2", //
			"2.12.0", //
			"2.12.1", //
			"2.12.2", //
			"2.13.0", //
			"2.13.1", //
			"2.13.2", //
			"2.13.3", //
			"2.14.0", //
			"2.14.1" //
	);

	CheckForJndiManagerWithDirContextLookups sut = new CheckForJndiManagerWithDirContextLookups();

	@Test
	void log4j16HasJndiManagerWithDirContextLookups() throws Exception {
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(detections.getDetections())
				.containsExactly(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutDirContextLookups));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class /org/apache/logging/log4j/core/net/JndiManager.class",
				ref);
	}

}
