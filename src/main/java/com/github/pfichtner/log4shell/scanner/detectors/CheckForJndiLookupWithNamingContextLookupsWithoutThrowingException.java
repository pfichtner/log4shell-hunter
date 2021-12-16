package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.nameIsLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.namingContext;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class CheckForJndiLookupWithNamingContextLookupsWithoutThrowingException implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiLookup.class")) {
			hasJndiManagerLookupImpl(classNode, nameIsLookup, namingContext).stream().filter(Optional::isPresent)
					.map(Optional::get).forEach(n -> detections.add(this, filename, n));
		}
	}

	@Override
	public String format(Detection detection) {
		return "Reference to " + methodName((MethodInsnNode) detection.getObject());
	}

}
