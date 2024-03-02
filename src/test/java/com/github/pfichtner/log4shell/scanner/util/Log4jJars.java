package com.github.pfichtner.log4shell.scanner.util;

import static com.vdurmont.semver4j.Semver.SemverType.LOOSE;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.File;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.vdurmont.semver4j.Semver;

public final class Log4jJars implements Iterable<File> {

	private final File dir;
	private final List<File> log4jJars;

	private static final Log4jJars instance = new Log4jJars();

	private Log4jJars() {
		try {
			this.dir = new File(getClass().getClassLoader().getResource("log4jars").toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException();
		}
		this.log4jJars = Arrays.stream(dir.list()).map(f -> new File(dir, f)).collect(toUnmodifiableList());
	}

	public static Log4jJars getInstance() {
		return instance;

	}

	public File getDir() {
		return dir;
	}

	public List<File> getLog4jJars() {
		return log4jJars;
	}

	public File version(String version) {
		String filename = "log4j-core-" + version + ".jar";
		return log4jJars.stream().filter(hasFilename(filename)).findFirst()
				.orElseThrow(() -> new NoSuchElementException(filename));
	}

	public List<File> versions(String... versions) {
		return sortedList(Arrays.stream(versions).map(this::version));
	}

	private static Predicate<File> hasFilename(String filename) {
		return f -> f.getName().equals(filename);
	}

	@Override
	public Iterator<File> iterator() {
		return sortedList(log4jJars.stream()).iterator();
	}

	private List<File> sortedList(Stream<File> stream) {
		return stream.sorted(comparing(Log4jJars::comparableVersion)).collect(toList());
	}

	private static Semver comparableVersion(File file) {
		return comparableVersion(file.getName());
	}

	private static Semver comparableVersion(String filename) {
		String simpleName = removeSuffix(filename);
		int firstDot = simpleName.indexOf('.');
		int lastDash = firstDot < 0 ? simpleName.length() : simpleName.substring(0, firstDot).lastIndexOf('-');
		return new Semver(simpleName.substring(lastDash + 1), LOOSE);
	}

	private static String removeSuffix(String filename) {
		return filename.substring(0, filename.lastIndexOf('.'));
	}

	public List<File> getLog4jJarsWithout(List<File> ignore) {
		return Util.ignore(log4jJars, ignore);
	}

	public List<File> getLog4jJarsVersionFrom(String version) {
		Semver thisOrHigher = new Semver(version, LOOSE);
		return log4jJars.stream().filter(f -> comparableVersion(f).isGreaterThanOrEqualTo(thisOrHigher))
				.collect(toList());
	}

}
