package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static org.approvaltests.Approvals.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import org.approvaltests.core.Options;
import org.approvaltests.core.Options.FileOptions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Entry;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class CVEDetectorTest {

	// https://logging.apache.org/log4j/2.x/security.html

	// 2021-12-14 2.12.2, the message lookups feature has been completely removed.

	// 2021-12-09 2.15.0, restricts JNDI LDAP lookups to localhost by default.

	// 2021-12-13 2.16.0, the message lookups feature has been completely removed.
	// JndiManager, called by Interpolar#Interpolator(StrLookup defaultLookup,
	// List<String> pluginPackages)
	// public static boolean isJndiEnabled() {
	// return PropertiesUtil.getProperties().getBooleanProperty("log4j2.enableJndi",
	// false);
	// }

	private static final String SEPARATOR = ",";

	Log4jJars log4jJars = Log4jJars.getInstance();

	@Test
	@Disabled
	void test() {
		// TODO File walker wrap
		// TODO in jar
		// TODO in directory/jar
		// TODO in directory/directory/jar
		// TODO in directory/directory/jar/jar/jar

		// TODO mix in one JAR: Self compiled, different versions of log4j +
		// self compiled +
		// own class with and without Annotation

	}

	@Test
	void detectsAndPrintsViaPluginDetection() {
		CVEDetector sut = new CVEDetector(new Log4jPluginAnnotation());
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).endsWith("/log4j-core-2.10.0.jar: " + expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).endsWith("/log4j-core-2.14.1.jar: " + expected) //
		);

	}

	@Test
	void detectsAndPrintsViaCheckForCalls() {
		CVEDetector sut = new CVEDetector(new JndiManagerLookupCalls());
		String expected = "Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).endsWith("/log4j-core-2.10.0.jar: " + expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).endsWith("/log4j-core-2.14.1.jar: " + expected));
	}

	@Test
	@Disabled
	void nested() throws Exception {
		CVEDetector sut = new CVEDetector(allDetectors());
		String sysout = tapSystemOut(() -> sut.check(new File(getClass().getClassLoader()
				.getResource("log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip")
				.toURI())));
		assertThat(sysout).isNotEmpty().contains("XXX");
	}

	@Test
	void approveAll() throws IOException {
		Multiplexer multiplexer = allDetectors();
		verify(toBeApproved(new CVEDetector(multiplexer), multiplexer.getMultiplexed()), options());
	}

	private static Options options() {
		return new FileOptions(new HashMap<>()).withExtension(".csv");
	}

	private String toBeApproved(CVEDetector detector, List<AbstractDetector> detectors) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append(header(detector, detectors)).append("\n");
		for (File file : log4jJars) {
			sb.append(content(detector, detectors, file)).append("\n");
		}
		return sb.toString();
	}

	private String header(CVEDetector detector, List<AbstractDetector> detectors) {
		StringBuilder sb = new StringBuilder();
		sb.append("File").append(SEPARATOR);
		for (AbstractDetector visitor : detectors) {
			sb.append(visitor.getName()).append(SEPARATOR);
		}
		return sb.toString();
	}

	private String content(CVEDetector cveDetector, List<AbstractDetector> detectors, File log4jJar)
			throws IOException {
		List<Entry> detections = cveDetector.analyze(log4jJar.getAbsolutePath()).getEntries();
		StringBuilder sb = new StringBuilder();
		sb.append(log4jJar.getAbsoluteFile().getName()).append(SEPARATOR);
		for (AbstractDetector detector : detectors) {
			sb.append(contains(detections, detector) ? "X" : "").append(SEPARATOR);
		}
		return sb.toString();
	}

	private boolean contains(List<Entry> detections, Detector detector) {
		return detections.stream().map(Entry::getDetector).anyMatch(detector::equals);
	}

	private String runCheck(CVEDetector sut, String version) throws Exception {
		return tapSystemOut(() -> sut.check(log4jJars.version(version).getAbsolutePath()));
	}

}
