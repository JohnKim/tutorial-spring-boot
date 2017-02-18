package gsshop.web.jbp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import gsshop.web.jbp.security.service.UserService;

public class LimitLoginAuthenticationProvider extends DaoAuthenticationProvider {

	private static final Logger logger = LoggerFactory.getLogger(LimitLoginAuthenticationProvider.class);

	@Autowired
	UserService userService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		logger.debug("### LimitLoginAuthenticationProvider ### : " + authentication);

		try {
			Authentication auth = super.authenticate(authentication);

			// 로그인 성공했다면, failCount 를 리셋함.
			userService.resetFailAttempts(authentication.getName());
			return auth;
		} catch (BadCredentialsException e) {

			// 로그인 실패시, failCount 를 증가 시킨다.
			userService.updateFailAttempts(authentication.getName());
			throw e;

		} catch (LockedException e) {

			// 이미 잠겨 있는 경우,
			throw new LockedException("User account("+authentication.getName()+") is locked!");
		}

	}
}
