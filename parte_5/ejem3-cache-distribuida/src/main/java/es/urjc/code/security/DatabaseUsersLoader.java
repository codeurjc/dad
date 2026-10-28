package es.urjc.code.security;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DatabaseUsersLoader {

    @Autowired
    private UserRepository userRepository;

    @PostConstruct
    private void initDatabase() {
    	
    	userRepository.save(new AppUser("user", "pass", "ROLE_USER"));
		userRepository.save(new AppUser("admin", "adminpass", "ROLE_USER", "ROLE_ADMIN"));
    }

}
