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

class NamingContextLookupCallsFromJndiLookupTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithJndiLookups = log4jJars.versions( //
			"2.0-rc2", //
			"2.0", //
			"2.0.1", //
			"2.0.2" //
	);

	NamingContextLookupCallsFromJndiLookup sut = new NamingContextLookupCallsFromJndiLookup();

	@Test
	void log4j202HasJndiManagerWithContextLookups() throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		assertThat(getFormatted(detector.analyze(log4jJars.version("2.0.2").getAbsolutePath())))
				.singleElement(as(STRING)).startsWith(refTo("javax.naming.Context#lookup(java.lang.String)"));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class org.apache.logging.log4j.core.lookup.JndiLookup", ref);
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithJndiLookups.toArray(File[]::new));
	}

}
