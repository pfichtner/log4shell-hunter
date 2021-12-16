package com.github.pfichtner.log4shell.scanner;

import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static org.approvaltests.Approvals.verifyAll;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForJndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForJndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForJndiManagerWithDirContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForJndiManagerWithNamingContextLookups;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForLog4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.CheckForRefsToInitialContextLookups;
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
		CVEDetector sut = new CVEDetector(new CheckForLog4jPluginAnnotation());
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected) //
		);

	}

	@Test
	void detectsAndPrintsViaCheckForCalls() {
		CVEDetector sut = new CVEDetector(new CheckForJndiManagerLookupCalls());
		String expected = "Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected));
	}

	@Test
	void approveAll() {
		List<Detector<Detections>> detectors = Arrays.asList( //
				new CheckForJndiManagerLookupCalls(), //
				new CheckForJndiManagerWithNamingContextLookups(), //
				new CheckForJndiLookupWithNamingContextLookupsWithoutThrowingException(), //
				new CheckForJndiManagerWithDirContextLookups(), //
				new CheckForLog4jPluginAnnotation(), //
				new CheckForRefsToInitialContextLookups() //
		);

		CVEDetector detector = new CVEDetector(detectors);

		String header = header(detector);
		System.out.println(header);

		verifyAll(log4jJars.getLog4jJars().toArray(new File[0]), jar -> {
			try {
				String content = content(detector, jar);
				System.out.println(content);
				return content;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		});

	}

	private String header(CVEDetector detector) {
		StringBuilder sb = new StringBuilder();
		sb.append("\t");
		for (Detector<Detections> visitor : detector.getDetectors()) {
			sb.append(visitor.getName()).append("\t");
		}
		return sb.toString();
	}

	private String content(CVEDetector cveDetector, File log4jJar) throws IOException {
		List<Detection> detections = cveDetector.analyze(log4jJar.getAbsolutePath()).getDetections();
		StringBuilder sb = new StringBuilder();
		sb.append(log4jJar.getAbsoluteFile().getName()).append("\t");
		for (Detector<Detections> detector : cveDetector.getDetectors()) {
			sb.append(contains(detections, detector) ? "X" : "").append("\t");
		}
		return sb.toString();
	}

	private boolean contains(List<Detection> detections, Detector<Detections> detector) {
		return detections.stream().map(Detection::getDetector).anyMatch(detector::equals);
	}

	private String runCheck(CVEDetector sut, String version) throws Exception {
		return tapSystemOut(() -> sut.check(log4jJars.version(version).getAbsolutePath()));
	}

}
