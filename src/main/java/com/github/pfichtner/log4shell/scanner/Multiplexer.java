package com.github.pfichtner.log4shell.scanner;

import java.nio.file.Path;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;

public class Multiplexer extends AbstractDetector {

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
		for (AbstractDetector detector : detectors) {
			detector.visitEnd();
			detector.getDetections().forEach(this::addDetection);
		}
		super.visitEnd();
	}

}