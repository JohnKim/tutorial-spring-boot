package gsshop.web.jbp.security.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import gsshop.web.jbp.security.dto.User;

public interface UserService {

	User findUserByUsername(String username);
	Collection<GrantedAuthority> getAuthorities(String username);
	
	void updateFailAttempts(String username);
	void resetFailAttempts(String username);
	
	public PasswordEncoder passwordEncoder();
	
    public void createUser(User user);
    
}
