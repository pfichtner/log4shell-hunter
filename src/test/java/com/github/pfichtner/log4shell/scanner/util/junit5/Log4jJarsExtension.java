package com.github.pfichtner.log4shell.scanner.util.junit5;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

public class Log4jJarsExtension implements ParameterResolver {

	private static final Log4jJars log4jJars = Log4jJars.getInstance();

	@Override
	public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext)
			throws ParameterResolutionException {
		return parameterContext.getParameter().getType() == Log4jJars.class;
	}

	@Override
	public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext)
			throws ParameterResolutionException {
		return log4jJars;
	}

}
