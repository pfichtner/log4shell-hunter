package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.obfuscatorComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.STRING_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.hasRetentionPolicy;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.isAnno;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.returnTypeIs;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.PLUGIN_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.util.stream.Collectors.toList;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

/**
 * Searches for all classes that are annotated using log4j's
 * <code>@Plugin</code> annotation, where the annotation has
 * {@value #ATTR_NAME_VALUE} for the attribute {@value #ATTR_NAME_NAME} and
 * {@value #ATTR_CATEGORY_VALUE} for the attribute {@value #ATTR_CATEGORY_NAME}.
 */
public class Log4jPluginAnnotation extends AbstractDetector {

	private static final String ATTR_NAME_NAME = "name";
	private static final String ATTR_NAME_VALUE = "jndi";

	private static final String ATTR_CATEGORY_NAME = "category";
	private static final String ATTR_CATEGORY_VALUE = "Lookup";

	private static final Map<Object, Object> expectedAnnoContent = Map.of( //
			ATTR_NAME_NAME, ATTR_NAME_VALUE, //
			ATTR_CATEGORY_NAME, ATTR_CATEGORY_VALUE //
	);

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (hasPluginAnnotation(classNode)) {
			addDetection(filename, classNode, String.format("@Plugin(%s = \"%s\", %s = \"%s\")", //
					ATTR_NAME_NAME, ATTR_NAME_VALUE, ATTR_CATEGORY_NAME, ATTR_CATEGORY_VALUE));
		}
	}

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		AsmTypeComparator typeComparator = typeComparator();
		return (obfuscatorComparator.equals(typeComparator()) && couldBeLog4jPlugin(classNode))
				|| (hasPluginAnnotation(typeComparator, classNode,
						n -> typeComparator.isClass(Type.getType(n.desc), PLUGIN_TYPE)));
	}

	private static boolean hasPluginAnnotation(AsmTypeComparator typeComparator, ClassNode classNode,
			Predicate<AnnotationNode> predicate) {
		return nullSafety(classNode.visibleAnnotations).stream()
				.anyMatch(predicate.and(n -> typeComparator.annotationIs(n, expectedAnnoContent)));
	}

	// ----------------------------------------------------------------------------------------------------------

	private static boolean couldBeLog4jPlugin(ClassNode classNode) {
		if (!isAnno(classNode) || !hasRetentionPolicy(classNode, RUNTIME)) {
			return false;
		}
		// String name(); String category(); String elementType() default ""
		List<MethodNode> methodsThatReturnsStrings = classNode.methods.stream()
				.filter(n -> returnTypeIs(n, STRING_TYPE)).collect(toList());
		return methodsThatReturnsStrings.size() == 3 //
				&& methodsWithEmptyStringAsDefault(methodsThatReturnsStrings) == 1;
	}

	private static long methodsWithEmptyStringAsDefault(List<MethodNode> methods) {
		return methods.stream().filter(n -> "".equals(n.annotationDefault)).count();
	}

}
