package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.toMap;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.PLUGIN_TYPE;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

public class Log4jPluginAnnotation extends AbstractDetector {

	public static final String NAME_JNDI = "jndi";
	public static final String CATEGORY_LOOKUP = "Lookup";

	private static final Map<Object, Object> expectedAnnoContent = toMap(
			Arrays.asList("name", NAME_JNDI, "category", CATEGORY_LOOKUP));

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (hasPluginAnnotation(classNode)) {
			addDetections(filename, classNode, "@Plugin(name = \"" + NAME_JNDI + "\", category = \"" + CATEGORY_LOOKUP + "\")");
		}
	}

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		return hasPluginAnnotation(classNode, n -> typeComparator().isClass(Type.getType(n.desc), PLUGIN_TYPE));
	}

	public static boolean hasPluginAnnotation(ClassNode classNode, List<Type> annoTypes) {
		return hasPluginAnnotation(classNode, n -> annoTypes.contains(Type.getType(n.desc)));
	}

	private static boolean hasPluginAnnotation(ClassNode classNode, Predicate<AnnotationNode> predicate) {
		return nullSafety(classNode.visibleAnnotations).stream()
				.anyMatch(predicate.and(n -> typeComparator().annotationIs(n, expectedAnnoContent)));
	}

}
