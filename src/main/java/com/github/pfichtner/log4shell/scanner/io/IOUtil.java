package com.github.pfichtner.log4shell.scanner.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class IOUtil {

	private static final String JAR_FILE = ".jar";
	private static final String WAR_FILE = ".war";
	private static final String ZIP_FILE = ".zip";

	public static void copy(InputStream in, OutputStream out) throws IOException {
		byte[] buf = new byte[8 * 1024];
		int length;
		while ((length = in.read(buf)) > 0) {
			out.write(buf, 0, length);
		}
	}

	public static boolean isArchive(String currentEntry) {
		return currentEntry.endsWith(WAR_FILE) || currentEntry.endsWith(JAR_FILE) || currentEntry.endsWith(ZIP_FILE);
	}

}
