package com.sapient.photoapp.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import io.jsonwebtoken.Jwts;

public class AuthenticationFilter extends BasicAuthenticationFilter{
	
	//private UsersService usersService;
	private Environment environment;

	public AuthenticationFilter(Environment environment,
			AuthenticationManager authenticationManager) {
		super(authenticationManager);
		this.environment = environment;
		
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String authHeader = request.getHeader(environment.getProperty("auth.token.header.name"));
		if(authHeader==null || !authHeader.startsWith(environment.getProperty("auth.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken authentication  = getAuthentication(request);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
 	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String authHeader = request.getHeader(environment.getProperty("auth.token.header.name"));
		if(authHeader == null) {
			return null;
		}
		
		String token = authHeader.replace(environment.getProperty("auth.token.header.prefix"), "");
		String userId = Jwts.parser()
				.setSigningKey(environment.getProperty("token.secret")) //same token secret used while generating token
				.parseClaimsJws(token)
				.getBody()
				.getSubject();
		
		if(userId == null) {
			return null;
		}
				
		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}
	
	
	
	
	

}
