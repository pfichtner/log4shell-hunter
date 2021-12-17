package com.github.pfichtner.log4shell.scanner.io;

import static java.util.Arrays.asList;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

public final class Files {

	private static final List<String> archiveSuffixs = asList(".jar", ".war", ".zip", ".ear");

	private Files() {
		super();
	}

	public static boolean isArchive(File file) {
		return isArchive(file.getAbsolutePath());
	}

	public static boolean isArchive(String file) {
		return archiveSuffixs.stream().anyMatch(s -> file.endsWith(s));
	}

	public static boolean isClass(Path filename) {
		// TODO globs can have excludes ([!XXX])
		return filename.getFileSystem().getPathMatcher("glob:**.class").matches(filename)
				&& !isModuleInfoClass(filename);
	}

	public static boolean isModuleInfoClass(Path filename) {
		return filename.getFileSystem().getPathMatcher("glob:/module-info.class").matches(filename);
	}

}
