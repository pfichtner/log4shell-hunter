package com.github.pfichtner.log4shell.scanner;

import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Visitor;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerWithNamingContextLookups;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerWithDirContextLookups;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForLog4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForRefsToInitialContextLookups;

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
	void detectsAndPrintsViaPluginDetection() throws Exception {
		CVEDetector sut = new CVEDetector(new CheckForLog4jPluginAnnotation());
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected) //
		);

	}

	@Test
	void detectsAndPrintsViaCheckForCalls() throws Exception {
		CVEDetector sut = new CVEDetector(new CheckForJndiManagerLookupCalls());
		String expected = "Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class /org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected));
	}

	@Test
	// @Disabled("Could be converted to approval (but we have to sort by versions)")
	void all() throws Exception {
		List<Visitor<Detections>> vistors = Arrays.asList( //
				new CheckForJndiManagerLookupCalls(), //
				new CheckForJndiManagerWithNamingContextLookups(), //
				new CheckForJndiLookupWithNamingContextLookupsWithoutThrowingException(), //
				new CheckForJndiManagerWithDirContextLookups(), //
				new CheckForLog4jPluginAnnotation(), //
				new CheckForRefsToInitialContextLookups() //
		);

		String separator = "\t";
		System.out.print(separator);
		for (Visitor<Detections> visitor : vistors) {
			System.out.print(visitor.getName());
			System.out.print(separator);
		}
		System.out.println();

		CVEDetector sut = new CVEDetector(vistors);
		for (File log4jJar : log4jJars) {
			List<Detection> detections = sut.analyze(log4jJar.getAbsolutePath()).getDetections();
			System.out.print(log4jJar.getAbsoluteFile().getName());
			System.out.print(separator);
			for (Visitor<Detections> visitor : vistors) {
				System.out.print(detections.stream().filter(d -> d.getDetector().equals(visitor)).findAny()
						.map(_i -> "X").orElse(""));
				System.out.print(separator);

			}
			System.out.println();
		}
	}

	private String runCheck(CVEDetector sut, String version) throws Exception {
		return tapSystemOut(() -> sut.check(log4jJars.version(version).getAbsolutePath()));
	}

}
