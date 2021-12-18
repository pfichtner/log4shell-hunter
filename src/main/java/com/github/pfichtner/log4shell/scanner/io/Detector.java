package com.github.pfichtner.log4shell.scanner.io;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

public interface Detector {

	default String getName() {
		return getClass().getSimpleName();
	}

	void visit(String resource);

	void visitClass(Path filename, ClassNode classNode);

	void visitFile(Path file, byte[] bytes);

	void visitEnd();

}