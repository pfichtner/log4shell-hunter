package com.github.pfichtner.log4shell.scanner.util;

import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import java.util.Arrays;
import java.util.function.Predicate;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class LookupConstants {

	public static final String LOOKUP_NAME = "lookup";

	public static final Type PLUGIN_TYPE = Type.getObjectType("org/apache/logging/log4j/core/config/plugins/Plugin");

	public static final Type JNDI_LOOKUP_TYPE = Type.getObjectType("org/apache/logging/log4j/core/lookup/JndiLookup");

	public static final Type JNDI_MANAGER_TYPE = Type.getObjectType("org/apache/logging/log4j/core/net/JndiManager");

	private LookupConstants() {
		super();
	}

	public static Predicate<MethodNode> throwsNamingException() {
		return n -> Arrays.asList("javax/naming/NamingException").equals(n.exceptions);
	}

	public static Predicate<MethodInsnNode> isJndiManagerLookup(AsmTypeComparator typeComparator) {
		return n -> "(Ljava/lang/String;)Ljava/lang/Object;".equals(n.desc) //
				&& typeComparator.isClass(Type.getObjectType(n.owner), JNDI_MANAGER_TYPE)
				&& typeComparator.methodNameIs(n.name, LOOKUP_NAME) //
				&& opcodeIs(n, INVOKEVIRTUAL);
	}

	public static Predicate<MethodInsnNode> namingContextLookup() {
		return n -> "(Ljava/lang/String;)Ljava/lang/Object;".equals(n.desc) //
				&& ownerIs(n, "javax/naming/Context") //
				&& nameIs(n, LOOKUP_NAME) //
				&& opcodeIs(n, INVOKEINTERFACE); //
	}

	public static Predicate<MethodInsnNode> initialContextLookup() {
		return n -> "(Ljava/lang/String;)Ljava/lang/Object;".equals(n.desc) //
				&& ownerIs(n, "javax/naming/InitialContext") //
				&& nameIs(n, LOOKUP_NAME) //
				&& opcodeIs(n, INVOKEVIRTUAL); //
	}

	public static Predicate<MethodInsnNode> dirContextLookup() {
		return n -> ("(Ljava/lang/String;)Ljava/lang/Object;".equals(n.desc)
				|| "(Ljava/lang/String;)Ljavax/naming/directory/Attributes;".equals(n.desc)) //
				&& ownerIs(n, "javax/naming/directory/DirContext") //
				&& nameIs(n, LOOKUP_NAME) //
				&& opcodeIs(n, INVOKEINTERFACE);
	}

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
