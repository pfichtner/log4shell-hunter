package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static com.github.pfichtner.log4shell.scanner.Scrubbers.basedirScrubber;
import static com.github.pfichtner.log4shell.scanner.util.Util.captureAndRestoreAsmTypeComparator;
import static com.github.stefanbirkner.systemlambda.SystemLambda.catchSystemExit;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemErr;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.joining;
import static org.approvaltests.Approvals.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatRuntimeException;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.approvaltests.core.Options;
import org.approvaltests.core.Options.FileOptions;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.DefaultLocale;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

@DefaultLocale(language = "en")
class Log4ShellHunterTest {

	static final String STDERR = "stderr";
	static final String STDOUT = "stdout";
	static final String RC = "rc";

	static final String SEPARATOR = ",";

	@Test
	void detectsAndPrintsViaPluginDetection(Log4jJars log4jJars) {
		DetectionCollector collector = new DetectionCollector(new Log4jPluginAnnotation());
		String expected = "> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, log4jJars.version("2.10.0"))) //
						.contains("/log4j-core-2.10.0.jar") //
						.contains(expected), //
				() -> assertThat(runCheck(collector, log4jJars.version("2.14.1"))) //
						.contains("/log4j-core-2.14.1.jar") //
						.contains(expected) //
		);
	}

	@Test
	void detectsAndPrintsViaCheckForCalls(Log4jJars log4jJars) {
		DetectionCollector collector = new DetectionCollector(new JndiManagerLookupCallsFromJndiLookup());
		String expected = "> Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, log4jJars.version("2.10.0"))) //
						.contains("/log4j-core-2.10.0.jar") //
						.contains(expected), //
				() -> assertThat(runCheck(collector, log4jJars.version("2.14.1"))) //
						.contains("/log4j-core-2.14.1.jar") //
						.contains(expected) //
		);
	}

	@Test
	void nested() throws Exception {
		File zip = new File(getClass().getClassLoader()
				.getResource("log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip")
				.toURI());
		String[] out = runCheck(new DetectionCollector(new Multiplexer(allDetectors())), zip).split("\n");
		String refToContext = "> Reference to javax.naming.Context#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource ";
		String plugin = "> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource ";
		String constantPoolString = "> log4j2.enableJndi access found in class org.apache.logging.log4j.core.net.JndiManager in resource ";
		String refToJndiManager = "> Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource ";
		String refToDirContext = "> Reference to javax.naming.directory.DirContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource ";
		String refToInitialContext = "> Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource ";
		assertThat(out).containsExactly( //
				zip.toString(), //
				refToContext + nested(zip, "/log4j-core-2.12.2.jar"), //
				plugin + nested(zip, "/log4j-core-2.12.2.jar"), //
				constantPoolString + nested(zip, "/log4j-core-2.12.2.jar"), //
				refToJndiManager + nested(zip, "/log4j-core-2.16.0.jar"), //
				refToDirContext + nested(zip, "/log4j-core-2.16.0.jar"), //
				plugin + nested(zip, "/log4j-core-2.16.0.jar"), //
				constantPoolString + nested(zip, "/log4j-core-2.16.0.jar"), //
				plugin + nested(zip, "/log4j-core-2.0-beta9.jar"), //
				refToInitialContext + nested(zip, "/log4j-core-2.0-beta9.jar"));
	}

	@Test
	void throwsExceptionIfFileCannotBeRead() {
		String jar = "XXXXsomeNonExistentFileXXX.jar";
		assertThatRuntimeException().isThrownBy(() -> new Log4ShellHunter().check(new File(jar)))
				.withMessageContainingAll(jar, "not readable");
	}

	@Test
	void main() throws Exception {
		File zip = new File(getClass().getClassLoader()
				.getResource("log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip")
				.toURI());

		String out = tapSystemOut(
				() -> captureAndRestoreAsmTypeComparator(() -> Log4ShellHunter.main(zip.getAbsolutePath())));

		assertThat(out.split("\n")).containsExactly( //
				zip.toString(), //
				"> Possible 2.15 <= x <2.17.1 match found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource "
						+ nested(zip, "/log4j-core-2.16.0.jar"), //
				"> Possible 2.0-beta9, 2.0-rc1 match found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource "
						+ nested(zip, "/log4j-core-2.0-beta9.jar"));
	}

	static String nested(File zip, String string) {
		return zip.toURI() + "$" + string;
	}

	@Test
	void mainNoArgGiven() throws Exception {
		verifyMain();
	}

	@Test
	void printsHelp() throws Exception {
		verifyMain("-h");
	}

	@Test
	void mainInvalidMode() throws Exception {
		verifyMain("-m", "XXX-INVALID-MODE-XXX");
	}

	void verifyMain(String... args) throws Exception {
		verify(execMain(args));
	}

	String execMain(String... args) throws Exception {
		Map<String, String> values = new HashMap<>();
		captureAndRestoreAsmTypeComparator( //
				() -> //
				values.put(STDERR, tapSystemErr(() -> //
				values.put(STDOUT, tapSystemOut(() -> //
				values.put(RC, String.valueOf(catchSystemExit( //
						() -> Log4ShellHunter.main(args)))) //
				)))));
		return asList(STDOUT, STDERR, RC).stream()
				.map(h -> Stream.of(h, "-".repeat(h.length()), values.getOrDefault(h, "")).collect(joining("\n")))
				.collect(joining("\n"));
	}

	@Test
	void approveAll(Log4jJars log4jJars) throws IOException {
		Multiplexer multiplexer = new Multiplexer(allDetectors());
		verify(toBeApproved(new DetectionCollector(multiplexer), multiplexer.getMultiplexed(), log4jJars), csv());
	}

	@Test
	void approveLog4jDetector(Log4jJars log4jJars) throws IOException {
		Log4JDetector log4jDetector = new Log4JDetector();
		DetectionCollector collector = new DetectionCollector(log4jDetector);
		StringBuilder sb = new StringBuilder();
		for (File file : log4jJars) {
			String detected = collector.analyze(file.getAbsolutePath()).stream().map(Detection::format)
					.collect(joining(SEPARATOR));
			sb.append(file.getAbsoluteFile().getName() + ": " + (detected.isEmpty() ? "-" : detected)).append("\n");
		}
		verify(sb.toString(), options());
	}

	static Options options() throws MalformedURLException {
		return new Options(basedirScrubber());
	}

	static Options csv() {
		return new FileOptions(new HashMap<>()).withExtension(".csv");
	}

	String toBeApproved(DetectionCollector collector, Collection<AbstractDetector> detectors, Iterable<File> log4jJars)
			throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append(header(collector, detectors)).append("\n");
		for (File file : log4jJars) {
			sb.append(content(collector, detectors, file)).append("\n");
		}
		return sb.toString();
	}

	String header(DetectionCollector collector, Collection<AbstractDetector> detectors) {
		return "File" + SEPARATOR + //
				detectors.stream().map(AbstractDetector::getName).collect(joining(SEPARATOR));
	}

	String content(DetectionCollector collector, Collection<AbstractDetector> detectors, File jar) throws IOException {
		List<Detection> detections = collector.analyze(jar.getAbsolutePath());
		return jar.getAbsoluteFile().getName() + SEPARATOR //
				+ detectors.stream().map(d -> contains(detections, d) ? "X" : "").collect(joining(SEPARATOR));
	}

	boolean contains(List<Detection> detections, Detector detector) {
		return detections.stream().map(Detection::getDetector).anyMatch(detector::equals);
	}

	String runCheck(DetectionCollector collector, File file) throws Exception {
		return runCheck(new Log4ShellHunter(collector), file);
	}

	String runCheck(Log4ShellHunter log4jHunter, File file) throws Exception {
		return tapSystemOut(() -> log4jHunter.check(file));
	}

}
