package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerLookupCalls;

class CheckForJndiManagerLookupCallsTest {

	List<String> versionsWithoutJndiLookups = asList( //
			"log4j-core-2.0-alpha1.jar", //
			"log4j-core-2.0-alpha2.jar", //

			"log4j-core-2.0-beta1.jar", //
			"log4j-core-2.0-beta2.jar", //
			"log4j-core-2.0-beta3.jar", //
			"log4j-core-2.0-beta4.jar", //
			"log4j-core-2.0-beta5.jar", //
			"log4j-core-2.0-beta6.jar", //
			"log4j-core-2.0-beta7.jar", //
			"log4j-core-2.0-beta8.jar", //
			"log4j-core-2.0-beta9.jar", //

			"log4j-core-2.0-rc1.jar", //
			"log4j-core-2.0-rc2.jar", //

			// 2.0, 2.0.1, 2.0.2 (JndiManager#lookup(String) calls introduces with version
			// 2.1)
			// @Override
			// public String lookup(LogEvent event, String key) {
			// if (key == null) {
			// return null;
			// }
			//
			// Context ctx = null;
			// try {
			// ctx = new InitialContext();
			// return (String) ctx.lookup(convertJndiName(key));
			// } catch (NamingException e) {
			// return null;
			// } finally {
			// Closer.closeSilently(ctx);
			// }
			// }
			"log4j-core-2.0.jar", //
			"log4j-core-2.0.1.jar", //
			"log4j-core-2.0.2.jar", //

			// 2.12.2
			// @Override
			// public String lookup(LogEvent event, String key) {
			// LOGGER.warn("Attempt to use JNDI Lookup");
			// return RESULT;
			// }
			"log4j-core-2.12.2.jar" //

	);

	@Test
	void canDetectLookupCalls() throws Exception {
		Log4jJars log4jJars = Log4jJars.getInstance();
		CheckForJndiManagerLookupCalls sut = new CheckForJndiManagerLookupCalls();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutJndiLookups));
	}

}
