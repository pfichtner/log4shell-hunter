package com.github.pfichtner.log4shell.scanner.visitor;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

public final class AsmUtil {

	private AsmUtil() {
		super();
	}

	public static boolean isClass(String filename) {
		return filename.toLowerCase().endsWith(".class");
	}

	public static ClassNode readClass(byte[] bytes, int options) {
		ClassNode classNode = new ClassNode();
		new ClassReader(bytes).accept(classNode, options);
		return classNode;
	}

	public static Map<Object, Object> toMap(AnnotationNode annotationNode, List<Object> values) {
		return IntStream.range(0, values.size() / 2).boxed().collect(
				Collectors.toMap(i -> annotationNode.values.get(i * 2), i -> annotationNode.values.get(i * 2 + 1)));
	}

	public static <T> List<T> nullSafety(List<T> list) {
		return list == null ? Collections.emptyList() : list;
	}

}
