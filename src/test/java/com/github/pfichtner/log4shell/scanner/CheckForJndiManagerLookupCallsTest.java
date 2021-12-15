package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForJndiManagerLookupCalls;

class CheckForJndiManagerLookupCallsTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithoutJndiLookups = log4jJars.versions( //
			"2.0-alpha1", //
			"2.0-alpha2", //

			"2.0-beta1", //
			"2.0-beta2", //
			"2.0-beta3", //
			"2.0-beta4", //
			"2.0-beta5", //
			"2.0-beta6", //
			"2.0-beta7", //
			"2.0-beta8", //
			"2.0-beta9", //

			"2.0-rc1", //
			"2.0-rc2", //

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
			"2.0", //
			"2.0.1", //
			"2.0.2", //

			// 2.12.2
			// @Override
			// public String lookup(LogEvent event, String key) {
			// LOGGER.warn("Attempt to use JNDI Lookup");
			// return RESULT;
			// }
			"2.12.2" //

	);

	@Test
	void canDetectLookupCalls() throws Exception {
		CheckForJndiManagerLookupCalls sut = new CheckForJndiManagerLookupCalls();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutJndiLookups));
	}

}
