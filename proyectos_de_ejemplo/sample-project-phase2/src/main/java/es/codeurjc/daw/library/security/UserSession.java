package es.codeurjc.daw.library.security;

import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

import es.codeurjc.daw.library.model.User;

@Component
@SessionScope
public class UserSession {

    private User loggedUser;

    public boolean isLoggedUser() {
        return loggedUser != null;
    }

    public User getLoggedUser() {
        return loggedUser;
    }

    public void setLoggedUser(User loggedUser) {
        this.loggedUser = loggedUser;
    }
    
}
