package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.detectors.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.namingContextLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.JndiUtil.throwsNamingException;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class CheckForJndiManagerWithNamingContextLookups implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (filename.toString().endsWith("JndiManager.class")) {
			// TODO should be distinctBy target
			methodInsnNodes(classNode, methodNameIsLookup.and(throwsNamingException)).filter(namingContextLookup).distinct()
					.forEach(n -> detections.add(this, filename, n));
		}
	}

	@Override
	public String format(Detection detection) {
		return "Reference to " + methodName((MethodInsnNode) detection.getObject());
	}

}
