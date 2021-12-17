package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class MergebaseLog4jSamplesIT {

	@Test
	void checkSamples() throws IOException {
		CVEDetector sut = new CVEDetector(allDetectors());

		for (File subdir : Arrays.asList("false-hits", "old-hits", "true-hits").stream()
				.map(s -> new File("log4j-samples", s)).collect(toList())) {
			for (String name : sorted(subdir.list())) {
				File jar = new File(subdir, name);
				if (jar.isFile()) {
					System.out.println(jar);
					sut.check(jar);
					System.out.println();
				}
			}
		}

	}

	private static <T> T[] sorted(T[] elements) {
		Arrays.sort(elements);
		return elements;
	}

}
