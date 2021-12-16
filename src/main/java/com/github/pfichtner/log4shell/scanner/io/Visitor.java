package com.github.pfichtner.log4shell.scanner.io;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;

public interface Visitor<T> {

	default void visitClass(T detections, Path filename, ClassNode classNode) {
	}

	default void visitFile(Detections detections, Path file, byte[] bytes) {
	}

	String format(Path filename, Object data);

}