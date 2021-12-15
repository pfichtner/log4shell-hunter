package com.github.pfichtner.log4shell.scanner.util;

import static java.util.stream.Collectors.toList;

import java.io.File;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Predicate;
import java.util.stream.Stream;

public final class Log4jJars implements Iterable<File> {

	private String[] log4jJars;
	private File dir;

	private static final Log4jJars instance = new Log4jJars();

	private Log4jJars() {
		try {
			this.dir = new File(getClass().getClassLoader().getResource("log4jars").toURI());
			this.log4jJars = dir.list();
		} catch (URISyntaxException e) {
			throw new RuntimeException();
		}
	}

	public static Log4jJars getInstance() {
		return instance;

	}

	public File getDir() {
		return dir;
	}

	public String[] getLog4jJars() {
		return log4jJars.clone();
	}

	public File version(String version) {
		return stream().filter(hasFilename("log4j-core-" + version + ".jar")).findFirst()
				.orElseThrow(() -> new NoSuchElementException());
	}

	private static Predicate<File> hasFilename(String filename) {
		return f -> f.getName().equals(filename);
	}

	@Override
	public Iterator<File> iterator() {
		// TODO use Spliterator
		return stream().collect(toList()).iterator();
	}

	private Stream<File> stream() {
		return Arrays.asList(log4jJars).stream().map(f -> new File(dir, f));
	}

	public String[] getLog4jJarsWithout(List<String> ignore) {
		return Util.ignore(log4jJars, ignore);
	}

}
