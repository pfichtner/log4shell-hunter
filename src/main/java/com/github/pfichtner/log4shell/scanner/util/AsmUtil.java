package com.github.pfichtner.log4shell.scanner.util;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static java.util.Collections.emptyMap;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.joining;
import static org.objectweb.asm.Opcodes.ACC_ANNOTATION;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class AsmUtil {

	private AsmUtil() {
		super();
	}

	public static ClassNode readClass(byte[] bytes, int options) {
		ClassNode classNode = new ClassNode();
		new ClassReader(bytes).accept(classNode, options);
		return classNode;
	}

	public static Map<Object, Object> toMap(AnnotationNode annotationNode) {
		return annotationNode.values == null ? emptyMap() : toMap(annotationNode.values);
	}

	public static Map<Object, Object> toMap(List<Object> values) {
		return IntStream.range(0, values.size() / 2).boxed()
				.collect(Collectors.toMap(i -> values.get(i * 2), i -> values.get(i * 2 + 1)));
	}

	public static <T> List<T> nullSafety(List<T> list) {
		return list == null ? Collections.emptyList() : list;
	}

	public static String methodName(MethodInsnNode node) {
		Type methodType = Type.getMethodType(node.desc);
		String className = Type.getObjectType(node.owner).getClassName();
		String args = Arrays.stream(methodType.getArgumentTypes()).map(Type::getClassName).collect(joining(","));
		return className + "#" + node.name + "(" + args + ")";
	}

	public static Stream<MethodInsnNode> methodInsnNodes(ClassNode classNode, Predicate<MethodNode> methodFilter) {
		return methodInsnNode(
				classNode.methods.stream().filter(methodFilter).map(AsmUtil::instructionsStream).flatMap(identity()));
	}

	public static Stream<MethodInsnNode> methodInsnNode(Stream<AbstractInsnNode> instructions) {
		return Streams.filter(instructions, MethodInsnNode.class);
	}

	public static Stream<AbstractInsnNode> instructionsStream(MethodNode methodNode) {
		return Streams.itToStream(methodNode.instructions.iterator());
	}

	public static Stream<AbstractInsnNode> instructionsStream(InsnList instructions) {
		return Streams.itToStream(instructions.iterator());
	}

	public static boolean isAnno(ClassNode classNode) {
		return (classNode.access & ACC_ANNOTATION) != 0;
	}

	public static Predicate<LdcInsnNode> constantPoolLoadOf(Predicate<Object> predicate) {
		return n -> predicate.test(n.cst);
	}

	public static Predicate<MethodNode> isConstructor() {
		return n -> typeComparator().methodNameIs(n, "<init>");
	}

	public static Predicate<MethodNode> voidNoArgs() {
		return n -> n.desc.equals("()V");
	}

}
