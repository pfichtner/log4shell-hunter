package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection.getFormatted;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.obfuscatorComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.captureAndRestoreAsmTypeComparator;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;
import static org.junit.jupiter.api.Assertions.assertAll;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.util.Util.AltersComparatorMode;

class Log4jPluginAnnotationTest {

	AbstractDetector sut = new Log4jPluginAnnotation();

	@Test
	void log4j20beta9HasPluginWithDirectContextAccess(Log4jJars log4jJars) throws Exception {
		DetectionCollector detector = new DetectionCollector(sut);
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(getFormatted(detector.analyze(log4jJars.version("2.0-beta9").getAbsolutePath())))
						.singleElement(as(STRING)).startsWith(expected), //
				() -> assertThat(getFormatted(detector.analyze(log4jJars.version("2.16.0").getAbsolutePath())))
						.singleElement(as(STRING)).startsWith(expected) //

		);
	}

	@Test
	void canDetectPluginClass(Log4jJars log4jJars) throws Exception {
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.versionsHigherOrEqualTo("2.0-beta9"));
	}

	@Test
	@AltersComparatorMode
	void canDetectObfuscatedPluginClass() throws Exception {
		captureAndRestoreAsmTypeComparator(() -> {
			useTypeComparator(obfuscatorComparator);
			assertThat(new DetectionCollector(sut).analyze("my-log4j-samples/true-hits/somethingLikeLog4jPlugin.jar"))
					.singleElement().satisfies(d -> assertThat(d.format()).startsWith(
							"@Plugin(name = \"jndi\", category = \"Lookup\") found in class foo.SomethingThatCouldBeLog4PluginAnno"));
		});
	}

}
