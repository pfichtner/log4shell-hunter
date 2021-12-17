package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class JndiLookupWithNamingContextLookupsWithoutThrowingExceptionTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithJndiLookups = log4jJars.versions( //
			"2.0-rc2", //
			"2.0", //
			"2.0.1", //
			"2.0.2" //
	);

	JndiLookupWithNamingContextLookupsWithoutThrowingException sut = new JndiLookupWithNamingContextLookupsWithoutThrowingException();

	@Test
	void log4j202HasJndiManagerWithContextLookups() throws Exception {
		CVEDetector detector = new CVEDetector(sut);
		assertThat(detector.analyze(log4jJars.version("2.0.2").getAbsolutePath()).getFormatted())
				.containsExactly(refTo("javax.naming.Context#lookup(java.lang.String)"));
	}

	private static String refTo(String ref) {
		return String.format("Reference to %s found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class",
				ref);
	}

	@Test
	void canDetectLookupMethods() throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(versionsWithJndiLookups.toArray(new File[0]));
	}

}
