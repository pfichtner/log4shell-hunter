package com.github.pfichtner.log4shell.scanner.io;

import java.nio.file.Path;

public interface Visitor<T> {

	void visit(T detections, Path filename, byte[] bytes);

}