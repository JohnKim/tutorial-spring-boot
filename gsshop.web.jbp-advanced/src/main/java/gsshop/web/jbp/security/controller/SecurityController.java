package gsshop.web.jbp.security.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import gsshop.web.jbp.security.service.UserService;

@Controller
public class SecurityController {

	private static final Logger logger = LoggerFactory.getLogger(SecurityController.class);
	
	@Autowired UserService userService;

	@RequestMapping(value = { "/login" }, method = RequestMethod.GET)
	public String loginPage(ModelMap model, @RequestParam(value = "error", required = false) String error, HttpServletRequest request) {

		if (error != null) {
			logger.debug(" >> Login Page << : " + getErrorMessage(request, "SPRING_SECURITY_LAST_EXCEPTION") );
			model.addAttribute("error", getErrorMessage(request, "SPRING_SECURITY_LAST_EXCEPTION"));
		}
		return "login";
	}
	
	@RequestMapping(value = { "/login/success" }, method = RequestMethod.GET)
	public String locinSuccess(ModelMap model, Authentication authentication) {
		
		// USER 권한이 있다면, '/dashboard' 화면으로 이동
		if(authentication.getAuthorities().contains(new SimpleGrantedAuthority("USER"))) {
			return "redirect:/dashboard";
		}
		
		return "password";
	}
	

	@RequestMapping(value = { "/login/username" }, method = RequestMethod.GET)
	@ResponseBody
	public String user(Authentication authentication) {
		return authentication.getName();
	}

	@RequestMapping(value = { "/debug/encode/{string}" }, method = RequestMethod.GET)
	@ResponseBody
	public String encode(@PathVariable String string) {
		return userService.passwordEncoder().encode(string);
	}

	
	private String getErrorMessage(HttpServletRequest request, String key){

		Exception exception = (Exception) request.getSession().getAttribute(key);

		String error = "";
		if (exception instanceof BadCredentialsException) {
			error = "Invalid username and password!";
		}else if(exception instanceof LockedException) {
			error = exception.getMessage();
		}else{
			error = "Invalid username and password!";
		}

		return error;
	}

}