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
import pl.ark.chr.glassfish.realm.pam.util.PamConstants;
import pl.ark.chr.glassfish.realm.pam.util.RealmWrapper;

/**
 *
 * @author Arek
 */
@Service(name = "UniversalPamRealm")
public class PamRealm extends AppservRealm {

    public static final String NUMBER_OF_REALMS = "number_of_realms";
    public static final String REALM_BASENAME = "realm_";

    private List<RealmWrapper> registeredRealms = new ArrayList<>();
    private RealmResolver realmResolver = new RealmResolver();
    private Map<String, Vector> groupCache;

    @Override
    public void init(Properties props) throws BadRealmException, NoSuchRealmException {
        _logger.info("Configuring UnversalPamRealm.");
        super.setProperty(JAAS_CONTEXT_PARAM, props.getProperty(JAAS_CONTEXT_PARAM));

        int numberOfRealms = Integer.parseInt(props.getProperty(NUMBER_OF_REALMS));

        for (int i = 0; i < numberOfRealms; i++) {
            String realmKey = REALM_BASENAME + Integer.toString(i);
            String realmProperties = props.getProperty(realmKey);
            if (realmProperties == null) {
                throw new NoSuchRealmException("No properties found for realm: " + realmKey);
            }
            registeredRealms.add(realmResolver.resolveRealm(realmProperties));
        }

//        registeredRealms = setRealmsOrder(registeredRealms);

        groupCache = new HashMap<>();
    }

    @Override
    public String getAuthType() {
        _logger.info("Getting auth type");
        return "Universal Pam Realm";
    }

    public String[] authenticate(String username, char[] password) throws LoginException {
        List<String> allGroups = new ArrayList<>();
        
        boolean optionalNegative = false;
        boolean requiredFailed = false;
        for (RealmWrapper registeredRealmWrapper : registeredRealms) {
            String[] groups = null;
            Realm registeredRealm = registeredRealmWrapper.getRealm();
            if (registeredRealm instanceof FileRealm) {
                groups = ((FileRealm) registeredRealm).authenticate(username, password);
            }
            if (registeredRealm instanceof LDAPRealm) {
                try {
                    groups = ((LDAPRealm) registeredRealm).findAndBind(username, password);
                } catch (LoginException ex) {
                    _logger.log(Level.FINEST, "Nothing to worry, not found in ldap.");
                }
            }
            if (registeredRealm instanceof JDBCRealm) {
                groups = ((JDBCRealm) registeredRealm).authenticate(username, password);
            }
            
            //Checking control values
            if (registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_REQUIRED) && groups == null) {
                requiredFailed = true;
            }
            
            if (registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_REQUISITE) && groups == null) {
                throw new LoginException("Login failed for: " + username + ". Requisite realm negative.");
            }
            
//            if (registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_SUFFICIENT) && groups == null) {
//                sufficientNegative = true;
//            } else 
                if (registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_SUFFICIENT)) {
//                sufficientNegative = false;
                break;
            }

            if (registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_OPTIONAL) && allGroups.isEmpty() && groups == null) {
                optionalNegative = true;
            } else if(registeredRealmWrapper.getControlValue().equals(PamConstants.CONTROL_OPTIONAL) && allGroups.isEmpty()) {
                optionalNegative = false;
            }

            if (groups != null) {
                allGroups.addAll(Arrays.asList(groups));
            }
        }
        
        if (requiredFailed) {
            throw new LoginException("Login failed for: " + username + ". Required realm negative.");
        }
//        if(sufficientNegative) {
//            throw new LoginException("Login failed for: " + username + ". Last suffiecient realm negative.");
//        }
        if(allGroups.isEmpty() && optionalNegative) {
            throw new LoginException("Login failed for: " + username + ". Optional realm negative.");
        }
        setGroupNames(username, (String[]) allGroups.toArray());
        return (String[]) allGroups.toArray();
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

        synchronized (this) {
            groupCache.put(username, userGroups);
        }
    }

    private List<RealmWrapper> setRealmsOrder(List<RealmWrapper> registeredRealms) {
        List<RealmWrapper> orderedList = new ArrayList<>();
        orderedList.addAll(getAllWithControlValue(registeredRealms, PamConstants.CONTROL_REQUIRED));
        orderedList.addAll(getAllWithControlValue(registeredRealms, PamConstants.CONTROL_REQUISITE));
        orderedList.addAll(getAllWithControlValue(registeredRealms, PamConstants.CONTROL_SUFFICIENT));
        orderedList.addAll(getAllWithControlValue(registeredRealms, PamConstants.CONTROL_OPTIONAL));
        return orderedList;
    }

    private List<RealmWrapper> getAllWithControlValue(List<RealmWrapper> registeredRealms, String controlValue) {
        List<RealmWrapper> orderedList = new ArrayList<>();
        for (RealmWrapper registeredRealm : registeredRealms) {
            if (registeredRealm.getControlValue().equals(controlValue)) {
                orderedList.add(registeredRealm);
            }
        }
        return orderedList;
    }

}
