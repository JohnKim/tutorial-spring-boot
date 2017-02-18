package gsshop.web.jbp.security.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import gsshop.web.jbp.security.dto.User;
import gsshop.web.jbp.security.mapper.UserMapper;

@Service
public class UserServiceImpl implements UserService {

	private PasswordEncoder passwordEncoder = new SHAPasswordEncoder(256); //new BCryptPasswordEncoder();

	@Autowired UserMapper userMapper;

	@Override
	public User findUserByUsername(String username) {
		User user = userMapper.readUser(username);
		if(user != null) user.setAuthorities(getAuthorities(username));
		return user;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities(String username) {
		List<String> string_authorities = userMapper.readAuthority(username);
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		for (String authority : string_authorities) {
			authorities.add(new SimpleGrantedAuthority(authority));
		}
		return authorities;
	}

	@Override
	public void createUser(User user) {
		String rawPassword = user.getPassword();
		String encodedPassword = new BCryptPasswordEncoder().encode(rawPassword);
		user.setPassword(encodedPassword);
		userMapper.createUser(user);
		userMapper.createAuthority(user);
	}

	@Override
	public PasswordEncoder passwordEncoder() {
		return this.passwordEncoder;
	}

	@Override
	public void updateFailAttempts(String username) {
		userMapper.updateFailCount(username);
		
	}

	@Override
	public void resetFailAttempts(String username) {
		userMapper.resetFailCount(username);
	}


}
