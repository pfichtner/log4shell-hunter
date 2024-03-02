package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class DirContextLookupsCallsFromJndiManagerTest {

	DirContextLookupsCallsFromJndiManager sut = new DirContextLookupsCallsFromJndiManager();

	@Test
	void log4j16HasJndiManagerWithDirContextLookups(Log4jJars log4jJars) throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		List<Detection> detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(getFormatted(detections)).singleElement(as(STRING))
				.startsWith(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	@Test
	void canDetectLookupMethods(Log4jJars log4jJars) throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut))).containsOnlyKeys(versionsWithDirContextLookups(log4jJars));
	}

	static List<File> versionsWithDirContextLookups(Log4jJars log4jJars) {
		return log4jJars.versions( //
				"2.15.0", //
				"2.16.0" //
		);
	}

	static String refTo(String ref) {
		return format("Reference to %s found in class org.apache.logging.log4j.core.net.JndiManager", ref);
	}

}
