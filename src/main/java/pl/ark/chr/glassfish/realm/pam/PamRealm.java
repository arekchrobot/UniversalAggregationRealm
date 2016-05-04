package pl.ark.chr.glassfish.realm.pam;

import com.sun.appserv.security.AppservRealm;
import static com.sun.enterprise.security.BaseRealm.JAAS_CONTEXT_PARAM;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.Realm;
import com.sun.enterprise.security.auth.realm.file.FileRealm;
import com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm;
import com.sun.enterprise.security.auth.realm.ldap.LDAPRealm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
import javax.security.auth.login.LoginException;
import org.jvnet.hk2.annotations.Service;
import pl.ark.chr.glassfish.realm.pam.services.RealmResolver;

/**
 *
 * @author Arek
 */
@Service(name = "CustomizablePamRealm")
public class PamRealm extends AppservRealm {

    public static final String NUMBER_OF_REALMS = "number_of_realms";
    public static final String REALM_BASENAME = "realm_";
    
    private List<Realm> registeredRealms = new ArrayList<>();
    private RealmResolver realmResolver = new RealmResolver();
    private Map<String, Vector> groupCache;
    
    @Override
    public void init(Properties props) throws BadRealmException, NoSuchRealmException {
        _logger.info("Must implement this custom init method");
        super.setProperty(JAAS_CONTEXT_PARAM, props.getProperty(JAAS_CONTEXT_PARAM));
        
        int numberOfRealms = Integer.parseInt(props.getProperty(NUMBER_OF_REALMS));
        
        for (int i = 0; i < numberOfRealms; i++) {
            String realmKey = REALM_BASENAME + Integer.toString(i);
            String realmProperties = props.getProperty(realmKey);
            if(realmProperties == null) {
                throw new NoSuchRealmException("No properties found for realm: " + realmKey);
            }
            registeredRealms.add(realmResolver.resolveRealm(realmProperties));
        }
        
        groupCache = new HashMap<>();
    }

    @Override
    public String getAuthType() {
        _logger.info("Getting auth type");
        return "Customizable Pam Realm";
    }
    
    public String[] authenticate(String username, char[] password) throws LoginException {
        String[] groups = null;
        for (Realm registeredRealm : registeredRealms) {
            _logger.info("iside the loop");
            if(registeredRealm instanceof FileRealm) {
                groups = ((FileRealm)registeredRealm).authenticate(username, password);
                if(groups != null) {
                    _logger.info("authenticated using file realm");
                    setGroupNames(username, groups);
                    return groups;
                }
            }
            if(registeredRealm instanceof LDAPRealm) {
                try {
                    groups = ((LDAPRealm)registeredRealm).findAndBind(username, password);
                } catch(LoginException ex) {
                    _logger.log(Level.FINEST, "Nothing to worry, just not found in ldap");
                }
                if(groups != null) {
                    _logger.info("authenticated using ldap realm");
                    setGroupNames(username, groups);
                    return groups;
                }
            }
            if(registeredRealm instanceof JDBCRealm) {
                groups = ((JDBCRealm)registeredRealm).authenticate(username, password);
                if(groups != null) {
                    _logger.info("authenticated using jdbc realm");
                    setGroupNames(username, groups);
                    return groups;
                }
            }
        }
        throw new LoginException("Login failed for: " + username);
    }

    @Override
    public Enumeration getGroupNames(String username) throws InvalidOperationException, NoSuchUserException {
        _logger.info("Getting group names");
        Vector userGroups = groupCache.get(username);
        if (userGroups == null) {
            throw new NoSuchUserException("No groups found for user: " + username);
        }
        return userGroups.elements();
    }

    private void setGroupNames(String username, String[] groups) {
        Vector<String> userGroups = new Vector<>(groups.length + 1);
        userGroups.addAll(Arrays.asList(groups));
        
        synchronized(this) {
            groupCache.put(username, userGroups);
        }
    }

}
