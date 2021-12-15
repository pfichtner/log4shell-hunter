package com.github.pfichtner.log4shell.scanner;

import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForLog4jPluginAnnotation;

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
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected) //
		);

	}

	@Test
	void detectsAndPrintsViaCheckForCalls() throws Exception {
		CVEDetector sut = new CVEDetector(new CheckForJndiManagerLookupCalls());
		String expected = "Reference to org/apache/logging/log4j/core/net/JndiManager found in class org/apache/logging/log4j/core/lookup/JndiLookup.class\n";
		assertAll( //
				() -> assertThat(runCheck(sut, "2.10.0")).isEqualTo(expected), //
				() -> assertThat(runCheck(sut, "2.14.1")).isEqualTo(expected));
	}

	private String runCheck(CVEDetector sut, String version) throws Exception {
		return tapSystemOut(() -> sut.check(Log4jJars.getInstance().version(version).getAbsolutePath()));
	}

}
