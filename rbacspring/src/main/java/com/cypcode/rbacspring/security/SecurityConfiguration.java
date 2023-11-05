package com.cypcode.rbacspring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JWTRequestFilter jwtRequestFilter;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		final List<GlobalAuthenticationConfigurerAdapter> configurers = new ArrayList<>();
		configurers.add(new GlobalAuthenticationConfigurerAdapter() {
			@Override
			public void configure(AuthenticationManagerBuilder auth) throws Exception {
				auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
			}
		});
		return authConfig.getAuthenticationManager();
	}

	private void sharedSecurityConfiguration(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf(AbstractHttpConfigurer::disable).cors().configurationSource(corsConfigurationSource()).and()
				.sessionManagement(httpSecuritySessionManagementConfigurer -> {
					httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
				});
	}

	@Bean
	public SecurityFilterChain securityFilterChainGlobalAPI(HttpSecurity httpSecurity) throws Exception {
		sharedSecurityConfiguration(httpSecurity);
		httpSecurity.securityMatcher("user", "admin").authorizeHttpRequests(auth -> {
			auth.anyRequest().authenticated();
		}).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}
	
	@Bean
	public SecurityFilterChain securityFilterChainGlobalAdminAPI(HttpSecurity httpSecurity) throws Exception {
		sharedSecurityConfiguration(httpSecurity);
		httpSecurity.securityMatcher("admin/**").authorizeHttpRequests(auth -> {
			auth.anyRequest()
			.hasRole("ADMIN");
		}).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}

	@Bean
	public SecurityFilterChain securityFilterChainGlobalUserProfileAPI(HttpSecurity httpSecurity) throws Exception {
		sharedSecurityConfiguration(httpSecurity);
		httpSecurity.securityMatcher("user/profile").authorizeHttpRequests(auth -> {
			auth.anyRequest()
			.hasRole("USER");
		}).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}
	@Bean
	public SecurityFilterChain securityFilterChainLoginAPI(HttpSecurity httpSecurity) throws Exception {
		sharedSecurityConfiguration(httpSecurity);
		httpSecurity.securityMatcher("/user/authenticate").authorizeHttpRequests(auth -> {
			auth.anyRequest().permitAll();
		}).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}

	@Bean
	public SecurityFilterChain securityFilterChainRegisterAPI(HttpSecurity httpSecurity) throws Exception {
		sharedSecurityConfiguration(httpSecurity);
		httpSecurity.securityMatcher("/user/register").authorizeHttpRequests(auth -> {
			auth.anyRequest().permitAll();
		}).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOrigins(Collections.singletonList("*"));
		configuration.setAllowedMethods(Collections.singletonList("*"));
		configuration.setAllowedHeaders(Collections.singletonList("*"));

		configuration.addAllowedOrigin("*");
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);

		return source;
	}
}
