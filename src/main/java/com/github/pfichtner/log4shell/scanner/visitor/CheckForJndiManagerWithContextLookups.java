package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.isClass;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.readClass;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.dirContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.namingContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.throwsNamingException;

import java.nio.file.Path;
import java.util.Optional;

import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerWithContextLookups implements Visitor<Detections> {

	interface MethodInsnNodeComparator {
		String handle(MethodInsnNode node);
	}

	private final MethodInsnNodeComparator[] nodeComparators;

	public CheckForJndiManagerWithContextLookups() {
		this(namingContext, dirContext);
	}

	public CheckForJndiManagerWithContextLookups(MethodInsnNodeComparator... nodeComparators) {
		this.nodeComparators = nodeComparators.clone();
	}

	@Override
	public void visit(Detections detections, Path filename, byte[] bytes) {
		// TODO do not depend on filename (classname)
		if (isClass(filename) && filename.toString().endsWith("JndiManager.class")) {
			hasJndiManagerLookupImpl(readClass(bytes, 0), nameIsLookup.and(throwsNamingException), nodeComparators)
					.stream().filter(Optional::isPresent).map(Optional::get)
					.map(s -> s.concat(" found in class " + filename)).forEach(detections::add);
		}
	}

}
