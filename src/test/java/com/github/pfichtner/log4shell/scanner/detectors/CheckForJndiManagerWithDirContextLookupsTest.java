package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class CheckForJndiManagerWithDirContextLookupsTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithDirContextLookups = log4jJars.versions( //
			"2.15.0", //
			"2.16.0" //
	);

	CheckForJndiManagerWithDirContextLookups sut = new CheckForJndiManagerWithDirContextLookups();

	@Test
	void log4j16HasJndiManagerWithDirContextLookups() throws Exception {
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.16.0").getAbsolutePath());
		assertThat(detections.getFormatted())
				.containsExactly(refTo("javax.naming.directory.DirContext#lookup(java.lang.String)"));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class /org/apache/logging/log4j/core/net/JndiManager.class",
				ref);
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithDirContextLookups.toArray(new File[0]));
	}

}
