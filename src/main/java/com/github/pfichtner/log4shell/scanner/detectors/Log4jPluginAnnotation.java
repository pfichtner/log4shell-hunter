package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.defaultComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.toMap;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.PLUGIN_TYPE;

import java.nio.file.Path;
import java.util.Map;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

public class Log4jPluginAnnotation extends AbstractDetector {

	public static final String NAME_JNDI = "jndi";
	public static final String CATEGORY_LOOKUP = "Lookup";

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (hasPluginAnnotation(classNode)) {
			addDetections(filename, "@Plugin(name = \"" + NAME_JNDI + "\", category = \"" + CATEGORY_LOOKUP + "\")");
		}
	}

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		for (AnnotationNode annotationNode : nullSafety(classNode.visibleAnnotations)) {
			// TODO build a map of annotations and verify if they match the properties of
			// org.apache.logging.log4j.plugins.Plugin
			if (defaultComparator.isClass(Type.getType(annotationNode.desc), PLUGIN_TYPE)) {
				Map<Object, Object> values = toMap(annotationNode);
				// @Plugin(name = "jndi", category = "Lookup")
				// TODO on the obfuscated version: name and category could have any name
				if (NAME_JNDI.equals(values.get("name")) && CATEGORY_LOOKUP.equals(values.get("category"))) {
					return true;
				}
			}
		}
		return false;
	}

}
