package com.github.pfichtner.log4shell.scanner.util;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.joining;
import static org.objectweb.asm.Opcodes.ACC_ANNOTATION;
import static org.objectweb.asm.Opcodes.ACC_STATIC;
import static org.objectweb.asm.Type.VOID_TYPE;
import static org.objectweb.asm.Type.getReturnType;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
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

	public static final Type STRING_TYPE = Type.getType(String.class);

	private static final String voidNoArgs = Type.getMethodDescriptor(VOID_TYPE);

	private static final Type RETENTION_TYPE = Type.getType(Retention.class);
	private static final Type RETENTIONPOLICY_TYPE = Type.getType(RetentionPolicy.class);
	private static final Method RETENTION_VALUE_METHOD = loadMethod(Retention.class, "value");

	private AsmUtil() {
		super();
	}

	private static Method loadMethod(Class<?> clazz, String methodName) {
		try {
			return clazz.getMethod(methodName);
		} catch (NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public static ClassNode readClass(byte[] bytes, int options) {
		ClassNode classNode = new ClassNode();
		new ClassReader(bytes).accept(classNode, options);
		return classNode;
	}

	public static Type classType(ClassNode classNode) {
		return Type.getObjectType(classNode.name);
	}

	public static Map<Object, Object> extractValues(AnnotationNode annotationNode) {
		return annotationNode.values == null ? emptyMap() : toMap(annotationNode.values);
	}

	/**
	 * Converts a list of key/values pairs to a Map key/value.
	 * 
	 * @param values the list to transform, e.g. A,B,C,D
	 * @return map containing the passed key/value pairs, e.g. A=B,C=D
	 */
	public static Map<Object, Object> toMap(Iterable<Object> values) {
		Map<Object, Object> map = new HashMap<>();
		for (Iterator<Object> it = values.iterator(); it.hasNext();) {
			map.put(it.next(), it.next());
		}
		return map;
	}

	public static <T> List<T> nullSafety(List<T> list) {
		return list == null ? emptyList() : list;
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
		return instructionsStream(methodNode.instructions);
	}

	public static Stream<AbstractInsnNode> instructionsStream(InsnList instructions) {
		return Streams.itToStream(instructions.iterator());
	}

	public static Stream<AbstractInsnNode> nexts(AbstractInsnNode node) {
		return Stream.iterate(node, Objects::nonNull, AbstractInsnNode::getNext);
	}

	public static Stream<AbstractInsnNode> prevs(AbstractInsnNode node) {
		return Stream.iterate(node, Objects::nonNull, AbstractInsnNode::getPrevious);
	}

	public static boolean isAnno(ClassNode classNode) {
		return bitSetContains(classNode.access, ACC_ANNOTATION);
	}

	public static boolean isStatic(MethodNode classNode) {
		return bitSetContains(classNode.access, ACC_STATIC);
	}

	private static boolean bitSetContains(int flags, int flag) {
		return (flags & flag) != 0;
	}

	public static Predicate<LdcInsnNode> constantPoolLoadOf(Predicate<Object> predicate) {
		return n -> predicate.test(n.cst);
	}

	public static Predicate<MethodNode> isConstructor() {
		return n -> "<init>".equals(n.name);
	}

	public static boolean returnTypeIs(MethodNode methodNode, Type type) {
		return type.equals(getReturnType(methodNode.desc));
	}

	public static Predicate<MethodNode> voidNoArgs() {
		return n -> voidNoArgs.equals(n.desc);
	}

	public static boolean hasRetentionPolicy(ClassNode classNode, RetentionPolicy retentionPolicy) {
		return nullSafety(classNode.visibleAnnotations).stream()
				.anyMatch(a -> a.desc.equals(RETENTION_TYPE.getDescriptor()) //
						&& a.values.size() == 2 //
						&& a.values.get(0).equals(RETENTION_VALUE_METHOD.getName()) //
						&& isStringArrayEqualTo(a.values.get(1), RETENTIONPOLICY_TYPE.getDescriptor(),
								retentionPolicy.name()));
	}

	private static boolean isStringArrayEqualTo(Object object, String... strings) {
		return object instanceof String[] && Arrays.equals((String[]) object, strings);
	}

}
