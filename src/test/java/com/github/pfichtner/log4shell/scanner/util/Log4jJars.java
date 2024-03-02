package com.github.pfichtner.log4shell.scanner.util;

import static com.vdurmont.semver4j.Semver.SemverType.LOOSE;
import static java.util.Arrays.stream;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.File;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.vdurmont.semver4j.Semver;

public final class Log4jJars implements Iterable<File> {

	private final List<File> log4jJars;

	public Log4jJars() {
		this(stream(baseDirectory().list()).map(f -> new File(baseDirectory(), f)));
	}

	private Log4jJars(Stream<File> log4jJars) {
		this(log4jJars.collect(toList()));
	}

	private Log4jJars(List<File> log4jJars) {
		this.log4jJars = List.copyOf(log4jJars);
	}

	private static File baseDirectory() {
		try {
			return new File(Log4jJars.class.getClassLoader().getResource("log4jars").toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException();
		}
	}

	public File version(String version) {
		String filename = "log4j-core-" + version + ".jar";
		return log4jJars.stream().filter(hasFilename(filename)).findFirst()
				.orElseThrow(() -> new NoSuchElementException(filename));
	}

	public Log4jJars versions(String... versions) {
		return new Log4jJars(sortedList(stream(versions).map(this::version)));
	}

	private static Predicate<File> hasFilename(String filename) {
		return f -> f.getName().equals(filename);
	}

	@Override
	public Iterator<File> iterator() {
		return sortedList(log4jJars.stream()).iterator();
	}

	private List<File> sortedList(Stream<File> stream) {
		return stream.sorted(comparing(Log4jJars::comparableVersion)).collect(toUnmodifiableList());
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

	public Log4jJars not(Log4jJars remove) {
		return new Log4jJars(log4jJars.stream().filter(contains(remove.log4jJars).negate()));
	}

	private static <T> Predicate<T> contains(List<T> elements) {
		return elements::contains;
	}

	public Log4jJars and(Log4jJars others) {
		return new Log4jJars(Stream.of(log4jJars, others.log4jJars).flatMap(Collection::stream));
	}

	public Log4jJars versionsHigherOrEqualTo(String version) {
		Semver thisOrHigher = new Semver(version, LOOSE);
		return new Log4jJars(log4jJars.stream().filter(f -> comparableVersion(f).isGreaterThanOrEqualTo(thisOrHigher)));
	}

}
