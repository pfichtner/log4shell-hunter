package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess.LOG4J2_ENABLE_JNDI;
import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupWithNamingContextLookupsWithoutThrowingException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCalls;
import com.github.pfichtner.log4shell.scanner.detectors.RefsToInitialContextLookups;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class MergebaseLog4jSamplesIT {

	@Test
	void checkSamples() throws IOException {
		// TODO assert if right category (one of following)
		// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

		CVEDetector sut = new CVEDetector(combined());

		List<String> filenames = filenames();
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		for (String filename : filenames) {
			if (isArchive(filename)) {
				System.out.println("-- " + filename);
				sut.check(filename);
				System.out.println();
			} else {
				// System.err.println("Ignoring " + file);
			}
		}

	}

	private Detector<Detections> combined() {

		JndiManagerLookupCalls vuln1 = new JndiManagerLookupCalls();
		JndiLookupWithNamingContextLookupsWithoutThrowingException vuln2 = new JndiLookupWithNamingContextLookupsWithoutThrowingException();
		RefsToInitialContextLookups vuln3 = new RefsToInitialContextLookups();

		List<Detector<Detections>> vulns = Arrays.asList(vuln1, vuln2, vuln3);
		IsJndiEnabledPropertyAccess isJndiEnabledPropertyAccess = new IsJndiEnabledPropertyAccess();

		List<Detector<Detections>> all = new ArrayList<>(vulns);
		all.add(isJndiEnabledPropertyAccess);

		return new Detectors.Multiplexer(all) {

			@Override
			public void visitEnd(Detections detections) {

				List<Detector<?>> detectors = detections.getDetections().stream().map(d -> d.getDetector())
						.collect(toList());

				// if we have Detections on classes (Paths) one of vulns, this is vulnerable IF
				// NOT we also have isJndiEnabledPropertyAccess

				boolean isVuln = vulns.stream().anyMatch(v -> detectors.contains(v));
				boolean hasPropertyAccess = detectors.contains(isJndiEnabledPropertyAccess);

				if (isVuln && !hasPropertyAccess) {
					System.err.println(
							"Log4J version with context lookup found (without " + LOG4J2_ENABLE_JNDI + " check)");
				}

			}

		};

	}

	private List<String> filenames() throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get("log4j-samples"))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
