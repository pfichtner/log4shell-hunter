package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.nio.file.Files.walk;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static org.approvaltests.Approvals.verify;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
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
		return allModes().map(m -> () -> doCheck(filenames, m));
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

	private static Stream<AsmTypeComparator> allModes() {
		return EnumSet.allOf(AsmTypeComparator.class).stream();
	}

	private static void doCheck(List<String> filenames, AsmTypeComparator typeComparator) throws IOException {
		System.out.println("*** using " + typeComparator);
		Log4ShellHunter.main(args(filenames, typeComparator));
	}

	private static String[] args(List<String> filenames, AsmTypeComparator typeComparator) {
		List<String> args = new ArrayList<>(asList("-m", String.valueOf(typeComparator)));
		filenames.stream().filter(f -> isArchive(f)).forEach(args::add);
		return args.toArray(String[]::new);
	}

	private List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
