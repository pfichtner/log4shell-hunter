package com.github.pfichtner.log4shell.scanner.io;

import static java.util.Arrays.asList;

import java.nio.file.Path;
import java.util.List;

public final class Files {

	private static final List<String> archiveSuffixs = asList(".jar", ".war", ".zip", ".ear");

	private Files() {
		super();
	}

	public static boolean isArchive(Path path) {
		return isArchive(path.toString());
	}

	public static boolean isArchive(String file) {
		return archiveSuffixs.stream().anyMatch(s -> file.endsWith(s));
	}

	public static boolean isClass(Path filename) {
		// TODO globs can have excludes ([!XXX])
		return globMatch(filename, "glob:**.class") && !globMatch(filename, "glob:/module-info.class");
	}

	private static boolean globMatch(Path filename, String string) {
		return filename.getFileSystem().getPathMatcher(string).matches(filename);
	}

}
