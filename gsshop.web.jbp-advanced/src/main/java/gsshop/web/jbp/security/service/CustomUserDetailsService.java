package gsshop.web.jbp.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

	@Autowired
	private UserService userService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		gsshop.web.jbp.security.dto.User user = userService.findUserByUsername(username);

		logger.debug(" >> loadUserByUsername << : " + user);
		
		boolean isAccountNonLocked = true; // user.getFailCount() >= 6 ? false : true;

		return new User(
				user.getUsername(), 
				user.getPassword(), 
				user.isEnabled(), 
				user.isAccountNonExpired(), 
				user.isCredentialsNonExpired(), 
				isAccountNonLocked, 
				user.getAuthorities()
				);
	}

}
