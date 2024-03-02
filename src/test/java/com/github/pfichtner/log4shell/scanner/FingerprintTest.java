package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static com.github.pfichtner.log4shell.scanner.Fingerprint.getFingerprint;
import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;
import static org.approvaltests.Approvals.verify;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class FingerprintTest {

	@Test
	void onlyVersionsPreviousBeta209AreAllowedToHaveNoFingerprints(Log4jJars log4jJars) throws Exception {
		assertThat(analyse(log4jJars, new Multiplexer(allDetectors())).entrySet().stream().map(e -> toDetectors(e))
				.filter(e -> e.getValue().isEmpty()).collect(toMap(Entry::getKey, Entry::getValue)))
				.containsOnlyKeys(log4jJars.versions("2.0-alpha1", "2.0-alpha2", "2.0-beta1", "2.0-beta2", //
						"2.0-beta3", "2.0-beta4", "2.0-beta5", "2.0-beta6", "2.0-beta7", "2.0-beta8"));
	}

	private Entry<File, Set<Class<? extends AbstractDetector>>> toDetectors(Entry<File, List<Detection>> entry) {
		return Map.entry(entry.getKey(), getFingerprint(entry.getValue()).stream().map(Fingerprint::getDetectors)
				.flatMap(Collection::stream).collect(toSet()));
	}

	@Test
	void approveAll(Log4jJars log4jJars) throws IOException {
		Multiplexer multiplexer = new Multiplexer(allDetectors());
		verify(toBeApproved(new DetectionCollector(multiplexer), multiplexer.getMultiplexed(), log4jJars));
	}

	private String toBeApproved(DetectionCollector collector, Collection<AbstractDetector> detectors,
			Iterable<File> log4jJars) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (File jar : log4jJars) {
			List<String> fingerprint = getFingerprint(collector.analyze(jar.getAbsolutePath()));
			sb.append(jar.getAbsoluteFile().getName() + ":\t" + fingerprint.stream().sorted().collect(joining(",")))
					.append("\n");
		}
		return sb.toString();
	}

}
