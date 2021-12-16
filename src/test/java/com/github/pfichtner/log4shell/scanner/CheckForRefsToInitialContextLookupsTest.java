package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForRefsToInitialContextLookups;

public class CheckForRefsToInitialContextLookupsTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithInitialContextLookups = log4jJars.versions( //
			"2.0-beta9", //
			"2.0-rc1" //

	);

	CheckForRefsToInitialContextLookups sut = new CheckForRefsToInitialContextLookups();

	@Test
	void canDetectPluginClass() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithInitialContextLookups.toArray(File[]::new));
	}

	@Test
	void log4j20beta9HasPluginWithDirectContextAccess() throws Exception {
		CVEDetector detector = new CVEDetector(sut);
		Detections detections = detector.analyze(log4jJars.version("2.0-beta9").getAbsolutePath());
		assertThat(detections.getFormatted()).containsExactly(
				"Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class");
	}

}
