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
import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class DirContextLookupsCallsFromJndiManagerTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithDirContextLookups = log4jJars.versions( //
			"2.15.0", //
			"2.16.0" //
	);

	DirContextLookupsCallsFromJndiManager sut = new DirContextLookupsCallsFromJndiManager();

	@Test
	void log4j16HasJndiManagerWithDirContextLookups() throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		List<Detection> detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(getFormatted(detections)).singleElement(as(STRING))
				.startsWith(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class org.apache.logging.log4j.core.net.JndiManager", ref);
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithDirContextLookups.toArray(File[]::new));
	}

}
