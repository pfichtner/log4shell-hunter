package com.github.pfichtner.log4shell.scanner.io;

import static com.github.pfichtner.log4shell.scanner.io.IOUtil.copy;
import static com.github.pfichtner.log4shell.scanner.io.IOUtil.isArchive;
import static java.nio.file.Files.createTempDirectory;
import static java.nio.file.Files.walk;
import static java.util.Collections.list;
import static java.util.Collections.reverseOrder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarScanner<T> {

	private final List<Visitor<T>> visitors;

	public JarScanner(Collection<Visitor<T>> visitors) {
		this.visitors = new ArrayList<>(visitors);
	}

	public void visitArchive(String jar, T collector) throws IOException {
		try (JarFile zip = new JarFile(jar)) {
			String tmp = createTempDirectory("extractedjar").toFile().getAbsolutePath();
			try {
				for (JarEntry entry : list(zip.entries())) {
					String filename = entry.getName();
					File destFile = new File(tmp, filename);
					destFile.getParentFile().mkdirs();

					if (isArchive(filename)) {
						visitArchive(destFile.getAbsolutePath(), collector);
					} else if (!entry.isDirectory()) {
						copy(zip.getInputStream(entry), new FileOutputStream(destFile));
						FileInputStream fis = new FileInputStream(destFile);
						ByteArrayOutputStream bytes = new ByteArrayOutputStream();
						copy(fis, bytes);
						for (Visitor<T> visitor : visitors) {
							visitor.visit(collector, filename, bytes.toByteArray());
						}
					}
				}
			} finally {
				walk(Paths.get(tmp)).map(Path::toFile).sorted(reverseOrder(File::compareTo)).forEach(File::delete);
			}
		}
	}

}
