package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.approvaltests.Approvals.verify;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4jSamplesIT {

	@TestFactory
	Stream<DynamicTest> checkMergeBaseSamples() throws IOException {
		List<String> filenames = filenames("log4j-samples");
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		return forAllModes(() -> doCheck(filenames));

	}

	@TestFactory
	Stream<DynamicTest> checkMySamples() throws IOException {
		List<String> filenames = filenames("my-log4j-samples");
		return forAllModes(() -> doCheck(filenames));
	}

	private static void doCheck(List<String> filenames) throws IOException {
		doCheck(new CVEDetector(new Log4JDetector()), filenames);
	}

	@Test
	// Approvals has issues with dynamic tests, so run them on their own (again)
	void approveLog4jSamples() throws IOException {
		List<String> filenames = filenames("log4j-samples");
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		verify(collect(filenames));
	}

	@Test
	// Approvals has issues with dynamic tests, so run them on their own (again)
	void approveMyLog4jSamples() throws IOException {
		verify(collect(filenames("my-log4j-samples")));
	}

	private static String collect(List<String> filenames) {
		StringBuilder sb = new StringBuilder();
		execute(forAllModes(() -> sb.append(tapSystemOut(() -> doCheck(filenames)))));
		return sb.toString();
	}

	private static void execute(Stream<DynamicTest> dynamicTests) {
		dynamicTests.forEach(dt -> {
			try {
				dt.getExecutable().execute();
			} catch (Throwable t) {
				throw new RuntimeException(t);
			}
		});
	}

	private static Stream<DynamicTest> forAllModes(Executable executable) {
		return allModes().map(c -> createDynamicTest(executable, c));
	}

	private static DynamicTest createDynamicTest(Executable executable, AsmTypeComparator typeComparator) {
		return dynamicTest(typeComparator.name(), () -> {
			System.out.println("*** using " + typeComparator);
			AsmTypeComparator.useTypeComparator(typeComparator);
			executable.execute();
		});
	}

	private static Stream<AsmTypeComparator> allModes() {
		return EnumSet.allOf(AsmTypeComparator.class).stream();
	}

	private static void doCheck(CVEDetector sut, List<String> filenames) throws IOException {
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
