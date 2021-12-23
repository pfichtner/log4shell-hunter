package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4jSamplesIT {

	@TestFactory
	Stream<DynamicTest> checkMergeBaseSamples() throws IOException {
		return forAllModes(() -> {
			// TODO assert if right category (one of following)
			// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

			List<String> filenames = filenames("log4j-samples");
			assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
			doCheck(new CVEDetector(new Log4JDetector()), filenames);
		});

	}

	@TestFactory
	Stream<DynamicTest> checkMySamples() throws IOException {
		return forAllModes(() -> {
			// TODO assert if right category (one of following)
			// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");
			doCheck(new CVEDetector(new Log4JDetector()), filenames("my-log4j-samples"));
		});

	}

	private Stream<DynamicTest> forAllModes(Executable executable) {
		return EnumSet.allOf(AsmTypeComparator.class).stream().map(c -> dynamicTest(c.name(), () -> {
			System.out.println("*** using " + c);
			AsmTypeComparator.useTypeComparator(c);
			executable.execute();
		}));
	}

	private void doCheck(CVEDetector sut, List<String> filenames) throws IOException {
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

	private List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
