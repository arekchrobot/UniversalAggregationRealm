package pl.ark.chr.glassfish.realm.pam.services;

import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.Realm;
import java.util.HashMap;
import java.util.Map;
import pl.ark.chr.glassfish.realm.pam.util.RealmWrapper;

/**
 *
 * @author Arek
 */
public class RealmResolver {

    private static final String MAP_SPLLITER = ";";
    private static final String KEY_VALUE_SPLLITER = "=";
    private static final String REALM_TYPE = "realm-type";
    private static final String CONTROL_VALUE = "control-value";

    private static final String JDBC_REALM = "jdbc";
    private static final String FILE_REALM = "file";
    private static final String LDAP_REALM = "ldap";

    public RealmWrapper resolveRealm(String properties) throws BadRealmException, NoSuchRealmException {
        Map<String, String> mappedProperties = resolveProperties(properties);

        return configureRealm(mappedProperties);
    }

    private Map<String, String> resolveProperties(String properties) throws BadRealmException {
        String[] keyValuePairs = properties.split(MAP_SPLLITER);

        Map<String, String> result = new HashMap<>();
        for (String keyValuePair : keyValuePairs) {
            String[] keyValue = keyValuePair.split(KEY_VALUE_SPLLITER, 2);
            if (keyValue.length != 2) {
                throw new BadRealmException("Wrong properties passed");
            }
            result.put(keyValue[0], keyValue[1]);
        }

        return result;
    }

    private RealmWrapper configureRealm(Map<String, String> mappedProperties) throws BadRealmException, NoSuchRealmException {
        String realmType = mappedProperties.get(REALM_TYPE);
        Realm newRealm = null;
        switch (realmType) {
            case JDBC_REALM: {
                newRealm = RealmFactory.configureJDBCRealm(mappedProperties);
                break;
            }
            case FILE_REALM: {
                newRealm = RealmFactory.configureFileRealm(mappedProperties);
                break;
            }
            case LDAP_REALM: {
                newRealm = RealmFactory.configureLDAPRealm(mappedProperties);
                break;
            }
        }

        if (newRealm == null) {
            throw new BadRealmException("No realm found with type: " + realmType);
        }
        RealmWrapper realmWrapper = new RealmWrapper();
        realmWrapper.setRealm(newRealm);
        realmWrapper.setControlValue(mappedProperties.get(CONTROL_VALUE));
        return realmWrapper;
    }
}
