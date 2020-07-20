package com.sapient.photoapp.api.gateway.security;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;



/*
 * Web Security configuration to enable requests to bypass spring security
 */
@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter{
	
	private Environment environment;
	//private UsersService usersService;
	//private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	public WebSecurity(Environment environment) {
		// TODO Auto-generated constructor stub
		this.environment = environment;
		//this.usersService = usersService;
		//this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		http.csrf().disable();
		http.headers().frameOptions().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		//configuring which urls to allow requests from and the type of requests
		http.authorizeRequests()
		.antMatchers(environment.getProperty("api.h2console.url.path")).permitAll()
		.antMatchers(HttpMethod.POST,environment.getProperty("api.registration.url.path")).permitAll()
		.antMatchers(HttpMethod.POST,environment.getProperty("api.login.url.path")).permitAll()
		.anyRequest().authenticated()
		.and()
		.addFilter(new AuthenticationFilter(environment, authenticationManager()));//any other request needs authentication
				
		//when specific ip needs to be allowed
		//http.authorizeRequests().antMatchers("/**").hasIpAddress(environment.getProperty("gateway.ip"));//TODO
		
	}

//	private AuthenticationFilter getAuthenticationFilter() throws Exception {
//		AuthenticationFilter authenticationFilter = new AuthenticationFilter(usersService, environment, authenticationManager());
//		//authenticationFilter.setAuthenticationManager(authenticationManager());
//		authenticationFilter.setFilterProcessesUrl(environment.getProperty("login.url.path"));  //custom url for login instead of the default /login
//		return authenticationFilter;
//	}
//
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(usersService).passwordEncoder(bCryptPasswordEncoder);
//	}

	
	
}
