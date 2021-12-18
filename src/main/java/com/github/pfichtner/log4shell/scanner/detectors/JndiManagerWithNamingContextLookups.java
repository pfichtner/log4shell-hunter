package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.classIsJndiManager;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.namingContextLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.throwsNamingException;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class JndiManagerWithNamingContextLookups implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (classIsJndiManager(filename)) {
			// TODO should be distinctBy target
			methodInsnNodes(classNode, methodNameIsLookup.and(throwsNamingException)).filter(namingContextLookup)
					.distinct().forEach(n -> detections.add(this, filename, Detector.referenceTo(n)));
		}
	}

}
