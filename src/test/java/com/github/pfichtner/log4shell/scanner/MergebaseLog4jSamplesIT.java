package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static java.nio.file.Files.walk;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

public class MergebaseLog4jSamplesIT {

	@Test
	void checkSamples() throws IOException {
		// TODO check if one of
		// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

		CVEDetector sut = new CVEDetector(allDetectors());
		try (Stream<Path> fileStream = walk(Paths.get("log4j-samples"))) {
			List<String> files = fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
			assumeFalse(files.isEmpty(), "git submodule empty, please clone recursivly");

			for (String file : files) {
				if (isArchive(file)) {
					System.out.println(file);
					sut.check(file);
					System.out.println();
				} else {
//					System.err.println("Ignoring " + file);
				}
			}

		}
	}

	private boolean isArchive(String file) {
		return asList(".jar", ".war", ".zip", ".ear").stream().anyMatch(s -> file.endsWith(s));
	}

}
