package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.approvaltests.Approvals.verify;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4jSamplesIT {

	@Test
	void approveLog4jSamples() throws Exception {
		List<String> filenames = filenames("log4j-samples");
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		verify(executeTapSysOut(allModesCheck(filenames)));
	}

	@Test
	void approveMyLog4jSamples() throws Exception {
		verify(executeTapSysOut(allModesCheck(filenames("my-log4j-samples"))));
	}

	private static Stream<Executable> allModesCheck(List<String> filenames) {
		return forAllModes(() -> doCheck(filenames));
	}

	private static void doCheck(List<String> filenames) throws IOException {
		doCheck(new DetectionCollector(new Log4JDetector()), filenames);
	}

	private static String executeTapSysOut(Stream<Executable> executables) throws Exception {
		return tapSystemOut(() -> execute(executables));
	}

	private static void execute(Stream<Executable> executables) {
		executables.forEach(e -> {
			try {
				e.execute();
			} catch (Throwable t) {
				throw new RuntimeException(t);
			}
		});
	}

	private static Stream<Executable> forAllModes(Executable executable) {
		return allModes().map(c -> () -> {
			System.out.println("*** using " + c);
			AsmTypeComparator.useTypeComparator(c);
			executable.execute();
		});
	}

	private static Stream<AsmTypeComparator> allModes() {
		return EnumSet.allOf(AsmTypeComparator.class).stream();
	}

	private static void doCheck(DetectionCollector sut, List<String> filenames) throws IOException {
		for (String filename : filenames) {
			if (isArchive(filename)) {
				System.out.println("-- " + filename);
				new Log4JHunter(sut).check(filename);
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
