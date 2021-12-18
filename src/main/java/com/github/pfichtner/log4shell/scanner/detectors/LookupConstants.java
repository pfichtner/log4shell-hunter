package com.github.pfichtner.log4shell.scanner.detectors;

import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.function.Predicate;

import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class LookupConstants {

	private static final String LOOKUP_NAME = "lookup";

	private LookupConstants() {
		super();
	}

	// TODO do not depend on method name
	public static final Predicate<MethodNode> methodNameIsLookup = methodNameIs(LOOKUP_NAME);

	// TODO do not depend on class name
	public static boolean classIsJndiLookup(Path filename) {
		return filename.toString().endsWith("JndiLookup.class");
	}

	// TODO do not depend on class name
	public static boolean classIsJndiManager(Path filename) {
		return filename.toString().endsWith("JndiManager.class");
	}

	public static Predicate<MethodNode> methodNameIs(String name) {
		return methodNode -> methodNode.name.equals(name);
	}

	public static final Predicate<MethodNode> throwsNamingException = methodNode -> Arrays
			.asList("javax/naming/NamingException").equals(methodNode.exceptions);

	public static final Predicate<MethodInsnNode> jndiManagerLookup = node -> //
	"(Ljava/lang/String;)Ljava/lang/Object;".equals(node.desc) //
//			&& ownerIs(node, "org/apache/logging/log4j/core/net/JndiManager") //
			&& (node.owner.endsWith("/JndiManager") || node.owner.equals("JndiManager")) //
			&& nameIs(node, LOOKUP_NAME) //
			&& opcodeIs(node, INVOKEVIRTUAL) //
	;

	public static final Predicate<MethodInsnNode> namingContextLookup = node -> //
	"(Ljava/lang/String;)Ljava/lang/Object;".equals(node.desc) //
			&& ownerIs(node, "javax/naming/Context") //
			&& nameIs(node, LOOKUP_NAME) //
			&& opcodeIs(node, INVOKEINTERFACE) //
	;

	public static final Predicate<MethodInsnNode> initialContextLookup = node -> //
	"(Ljava/lang/String;)Ljava/lang/Object;".equals(node.desc) //
			&& ownerIs(node, "javax/naming/InitialContext") //
			&& nameIs(node, LOOKUP_NAME) //
			&& opcodeIs(node, INVOKEVIRTUAL) //
	;

	public static final Predicate<MethodInsnNode> dirContextLookup = node -> //
	("(Ljava/lang/String;)Ljava/lang/Object;".equals(node.desc)
			|| "(Ljava/lang/String;)Ljavax/naming/directory/Attributes;".equals(node.desc)) //
			&& ownerIs(node, "javax/naming/directory/DirContext") //
			&& nameIs(node, LOOKUP_NAME) //
			&& opcodeIs(node, INVOKEINTERFACE) //
	;

	private static boolean nameIs(MethodInsnNode node, String name) {
		return name.equals(node.name);
	}

	private static boolean ownerIs(MethodInsnNode node, String type) {
		return type.equals(node.owner);
	}

	private static boolean opcodeIs(MethodInsnNode node, int opcode) {
		return opcode == node.getOpcode();
	}
}
