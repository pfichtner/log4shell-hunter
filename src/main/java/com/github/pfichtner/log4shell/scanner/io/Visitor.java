package com.github.pfichtner.log4shell.scanner.io;

public interface Visitor<T> {

	void visit(T detections, String filename, byte[] bytes);

}