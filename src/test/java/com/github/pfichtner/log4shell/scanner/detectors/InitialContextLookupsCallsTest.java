package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.combine;
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

class InitialContextLookupsCallsTest {

	InitialContextLookupsCalls sut = new InitialContextLookupsCalls();

	@Test
	void log4j20beta9HasPluginWithDirectContextAccess(Log4jJars log4jJars) throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		List<Detection> detections = detector.analyze(log4jJars.version("2.0-beta9").getAbsolutePath());
		assertThat(getFormatted(detections)).singleElement(as(STRING)).startsWith(
				"Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup");
	}

	@Test
	void canDetectPluginClass(Log4jJars log4jJars) throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithInitialContextLookups(log4jJars));
	}

	static List<File> versionsWithInitialContextLookups(Log4jJars log4jJars) {
		return combine(log4jJars.versions( //
				"2.0-beta9", //
				"2.0-rc1" //
		), log4jJars.versionsHigherOrEqualTo("2.17.0"));
	}

}
