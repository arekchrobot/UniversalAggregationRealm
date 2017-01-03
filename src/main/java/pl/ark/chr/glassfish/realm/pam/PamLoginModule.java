package pl.ark.chr.glassfish.realm.pam;

import com.sun.appserv.security.AppservPasswordLoginModule;
import java.util.logging.Level;
import javax.security.auth.login.LoginException;

/**
 *
 * @author Arek
 */
public class PamLoginModule extends AppservPasswordLoginModule{
    
    @Override
    protected void authenticateUser() throws LoginException {
        _logger.log(Level.INFO, "Authenticating user: {0}", _username);
        PamRealm realm = (PamRealm) _currentRealm;
        String[] grpList = realm.authenticate(_username, getPasswordChar());
        
        _logger.log(Level.INFO, "Commiting user {0} authentication", _username);
        commitUserAuthentication(grpList);
    }
}
