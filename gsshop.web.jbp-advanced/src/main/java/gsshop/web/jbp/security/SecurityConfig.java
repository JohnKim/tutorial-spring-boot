package gsshop.web.jbp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import gsshop.web.jbp.security.service.CustomUserDetailsService;
import gsshop.web.jbp.security.service.UserService;


@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired CustomUserDetailsService customUserDetailsService;
	@Autowired UserService userService;

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/css/**", "/js/**", "/lib/**", "/images/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers(
					"/dashboard/**",
					"/api/**"
					).hasAuthority("USER")
			.antMatchers(
					"/login/**"
					).hasAnyAuthority("USER", "TEMP")
		.and()
		.formLogin()
			.loginPage("/login").permitAll()
			.defaultSuccessUrl("/login/success", true)
		.and()
			.logout()
			.permitAll();
	}

	@Bean
	public LimitLoginAuthenticationProvider limitLoginAuthenticationProvider() throws Exception {
		LimitLoginAuthenticationProvider provider = new LimitLoginAuthenticationProvider();
		provider.setPasswordEncoder(userService.passwordEncoder());
		provider.setUserDetailsService(customUserDetailsService);
		return provider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(limitLoginAuthenticationProvider());
	}

}
