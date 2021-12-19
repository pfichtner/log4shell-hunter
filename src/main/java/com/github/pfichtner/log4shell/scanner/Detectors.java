package com.github.pfichtner.log4shell.scanner;

import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.DirContextLookupsCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupConstructorWithISException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiManager;

public final class Detectors {

	public static class Multiplexer extends AbstractDetector {

		private final List<AbstractDetector> detectors;

		public Multiplexer(List<AbstractDetector> detectors) {
			this.detectors = detectors;
		}

		public List<AbstractDetector> getMultiplexed() {
			return detectors;
		}

		@Override
		public void visit(String resource) {
			super.visit(resource);
			for (AbstractDetector detector : detectors) {
				detector.visit(resource);
			}
		}

		@Override
		public void visitFile(Path file, byte[] bytes) {
			super.visitFile(file, bytes);
			for (AbstractDetector detector : detectors) {
				detector.visitFile(file, bytes);
			}
		}

		@Override
		public void visitClass(Path filename, ClassNode classNode) {
			super.visitClass(filename, classNode);
			for (AbstractDetector detector : detectors) {
				detector.visitClass(filename, classNode);
			}
		}

		@Override
		public void visitEnd() {
			super.visitEnd();
			for (AbstractDetector detector : detectors) {
				detector.visitEnd();
			}
		}

		@Override
		public List<Detection> getDetections() {
			return detectors.stream().map(AbstractDetector::getDetections).flatMap(Collection::stream)
					.collect(toList());
		}

	}

	private static final List<AbstractDetector> detectors = unmodifiableList(Arrays.asList( //
			new JndiManagerLookupCallsFromJndiLookup(), //
			new NamingContextLookupCallsFromJndiManager(), //
			new NamingContextLookupCallsFromJndiLookup(), //
			new DirContextLookupsCallsFromJndiManager(), //
			new Log4jPluginAnnotation(), //
			new InitialContextLookupsCalls(), //
			new IsJndiEnabledPropertyAccess(), //
			new JndiLookupConstructorWithISException() //
	));

	private Detectors() {
		super();
	}

	public static Multiplexer allDetectors() {
		return multiplexer(detectors);
	}

	public static Multiplexer multiplexer(List<AbstractDetector> allDetectors) {
		return new Multiplexer(allDetectors);
	}

}
