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

public class InitialContextLookupsCallsTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithInitialContextLookups = log4jJars.versions( //
			"2.0-beta9", //
			"2.0-rc1", //
			"2.17.0", //
			"2.17.1" //
	);

	InitialContextLookupsCalls sut = new InitialContextLookupsCalls();

	@Test
	void log4j20beta9HasPluginWithDirectContextAccess() throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		List<Detection> detections = detector.analyze(log4jJars.version("2.0-beta9").getAbsolutePath());
		assertThat(getFormatted(detections)).singleElement(as(STRING)).startsWith(
				"Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup");
	}

	@Test
	void canDetectPluginClass() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithInitialContextLookups.toArray(File[]::new));
	}

}
