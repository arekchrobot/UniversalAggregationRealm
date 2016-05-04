package pl.ark.chr.glassfish.realm.pam;

import com.sun.appserv.security.AppservPasswordLoginModule;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 *
 * @author Arek
 */
public class PamLoginModule extends AppservPasswordLoginModule{
    
    private static final Logger logger = Logger.getLogger("PamLoginModule");
    
    @Override
    protected void authenticateUser() throws LoginException {
        logger.log(Level.INFO, "Authenticating user: {0}", _username);
        PamRealm realm = (PamRealm) _currentRealm;
        String[] grpList = realm.authenticate(_username, getPasswordChar());
        
        logger.log(Level.INFO, "Commiting user {0} authentication", _username);
        commitUserAuthentication(grpList);
    }
}
