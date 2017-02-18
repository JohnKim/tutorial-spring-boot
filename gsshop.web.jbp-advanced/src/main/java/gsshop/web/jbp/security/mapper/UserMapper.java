package gsshop.web.jbp.security.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import gsshop.web.jbp.security.dto.User;

@Mapper
public interface UserMapper {

	public User readUser(String username);
	public List<String> readAuthority(String username);
	
	public void updateFailCount(String username);
	public void resetFailCount(String username);

	public void createUser(User user);
	public void createAuthority(User user);

}