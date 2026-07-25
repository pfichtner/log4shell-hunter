package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.useTypeComparator;
import static org.kohsuke.args4j.OptionHandlerFilter.ALL;
import static org.kohsuke.args4j.ParserProperties.defaults;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
		private List<String> files = new ArrayList<>();
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
			}
			useTypeComparator(options.typeComparator);
			analyzeAndPrint(options.files);
		} catch (CmdLineException e) {
			parser.printUsage(System.err);
			System.exit(1);
		}
	}

	static void analyzeAndPrint(List<String> files) throws IOException {
		int threads = Runtime.getRuntime().availableProcessors();
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			List<Future<List<Detection>>> futures = new ArrayList<>();
			for (String file : files) {
				futures.add(executor.submit(() -> {
					DetectionCollector collector = new DetectionCollector(new Log4JDetector());
					return collector.analyze(new File(file));
				}));
			}

			for (int i = 0; i < files.size(); i++) {
				System.out.println(files.get(i));
				try {
					for (Detection detection : futures.get(i).get()) {
						System.out.println("> " + detection.format());
					}
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new IOException("Analysis interrupted", e);
				} catch (ExecutionException e) {
					Throwable cause = e.getCause();
					if (cause instanceof IOException) {
						throw (IOException) cause;
					}
					throw new IOException("Analysis failed for " + files.get(i), cause);
				}
				System.out.println();
			}
		} finally {
			executor.shutdown();
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
