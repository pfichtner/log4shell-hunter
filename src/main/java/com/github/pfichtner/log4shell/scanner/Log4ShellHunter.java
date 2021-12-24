package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
import static org.kohsuke.args4j.ParserProperties.defaults;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4ShellHunter {

	private final DetectionCollector detectionCollector;

	private static class Options {
		@Option(name = "-m", usage = "mode")
		private AsmTypeComparator typeComparator = AsmTypeComparator.repackageComparator;

		@Argument
		private List<String> files = new ArrayList<String>();
	}

	public static void main(String... args) throws IOException {
		Optional<Options> options = parseOptions(args);
		if (options.isEmpty()) {
			System.exit(1);
		}
		options.ifPresent(o -> {
			try {
				if (o.files.isEmpty()) {
					System.err.println("No filename given");
					System.exit(1);
				} else {
					useTypeComparator(o.typeComparator);
					Log4ShellHunter log4jHunter = new Log4ShellHunter();
					for (String file : o.files) {
						log4jHunter.check(file);
					}
				}
			} catch (Exception e) {
				System.err.println(e.getMessage());
			}
		});
	}

	private static Optional<Options> parseOptions(String... args) {
		Options options = new Options();
		CmdLineParser parser = new CmdLineParser(options, defaults().withUsageWidth(133));
		try {
			parser.parseArgument(args);
			return Optional.of(options);
		} catch (CmdLineException e) {
			parser.printUsage(System.err);
			return Optional.empty();
		}
	}

	public Log4ShellHunter() {
		this(new DetectionCollector(new Log4JDetector()));
	}

	public Log4ShellHunter(DetectionCollector detectionCollector) {
		this.detectionCollector = detectionCollector;
	}

	public void check(String jar) throws IOException {
		check(new File(jar));
	}

	public void check(File file) throws IOException {
		for (Detection detection : detectionCollector.analyze(file)) {
			System.out.println(file + ": " + detection.format());
		}
	}

}
