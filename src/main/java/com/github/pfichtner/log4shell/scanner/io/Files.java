package com.github.pfichtner.log4shell.scanner.io;

import static java.util.Arrays.asList;

import java.io.File;
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

}
