package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Scrubbers.basedirScrubber;
import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.pfichtner.log4shell.scanner.util.Util.captureAndRestoreAsmTypeComparator;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.concat;
import static org.approvaltests.Approvals.verify;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import org.approvaltests.core.Options;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

class Log4jSamplesIT {

	@Test
	void approveLog4jSamples() throws Exception {
		List<String> filenames = filenames("log4j-samples");
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		verify(executeTapSysOut(allModesCheck(filenames)), options());
	}

	@Test
	void approveMyLog4jSamples() throws Exception {
		verify(executeTapSysOut(allModesCheck(filenames("my-log4j-samples"))), options());
	}

	static Options options() throws MalformedURLException {
		return new Options(basedirScrubber());
	}

	static Stream<Executable> allModesCheck(List<String> filenames) {
		return allModes().map(m -> () -> doCheck(filenames, m));
	}

	static String executeTapSysOut(Stream<Executable> executables) throws Exception {
		return tapSystemOut(() -> execute(executables));
	}

	static void execute(Stream<Executable> executables) {
		executables.forEach(Log4jSamplesIT::tryExecute);
	}

	static void tryExecute(Executable executable) {
		try {
			executable.execute();
		} catch (Throwable throwable) {
			throw new RuntimeException(throwable);
		}
	}

	static Stream<AsmTypeComparator> allModes() {
		return EnumSet.allOf(AsmTypeComparator.class).stream();
	}

	static void doCheck(List<String> filenames, AsmTypeComparator typeComparator) throws Exception {
		System.out.println("*** using " + typeComparator);
		captureAndRestoreAsmTypeComparator(() -> Log4ShellHunter.main(args(filenames, typeComparator)));
	}

	static String[] args(List<String> filenames, AsmTypeComparator typeComparator) {
		Stream<String> modeArg = Stream.of("-m", String.valueOf(typeComparator));
		Stream<String> filesArg = filenames.stream().filter(f -> isArchive(f));
		return concat(modeArg, filesArg).toArray(String[]::new);
	}

	static List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).sorted().collect(toList());
		}
	}

}
