package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
import static org.kohsuke.args4j.OptionHandlerFilter.ALL;
import static org.kohsuke.args4j.ParserProperties.defaults;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4ShellHunter {

	private final DetectionCollector detectionCollector;

	private static class Options {
		@Option(name = "-h", help = true, usage = "prints this help", hidden = true)
		private boolean help;

		@Option(name = "-m", usage = "mode to compare class/method names")
		private AsmTypeComparator typeComparator = AsmTypeComparator.repackageComparator;

		@Argument(required = true, usage = "archives to analyze")
		private List<String> files = new ArrayList<String>();
	}

	public static void main(String... args) throws IOException {
		Options options = new Options();
		CmdLineParser parser = new CmdLineParser(options, defaults().withUsageWidth(133));
		try {
			parser.parseArgument(args);
			if (options.help) {
				parser.printUsage(System.out);
				parser.printExample(ALL);
				System.exit(0);
			} else if (options.files.isEmpty()) {
				System.err.println("No filename given");
				System.exit(1);
			} else {
				useTypeComparator(options.typeComparator);
				Log4ShellHunter log4jHunter = new Log4ShellHunter();
				for (String file : options.files) {
					log4jHunter.check(file);
				}
			}
		} catch (CmdLineException e) {
			parser.printUsage(System.err);
			System.exit(1);
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
		System.out.println(file);
		for (Detection detection : detectionCollector.analyze(file)) {
			System.out.println("> " + detection.format());
		}
		System.out.println();
	}

}
