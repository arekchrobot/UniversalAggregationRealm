package pl.ark.chr.glassfish.realm.pam.services;

import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.file.FileRealm;
import com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm;
import com.sun.enterprise.security.auth.realm.ldap.LDAPRealm;
import java.util.Map;
import java.util.Properties;

/**
 *
 * @author Arek
 */
public class RealmFactory {
    
    public static JDBCRealm configureJDBCRealm(Map<String, String> mappedProperties) throws BadRealmException, NoSuchRealmException {
        JDBCRealm jdbc = new JDBCRealm();
        
        Properties props = generateProperties(mappedProperties);
        
        jdbc.init(props);
        return jdbc;
    }
    
    public static FileRealm configureFileRealm(Map<String, String> mappedProperties) throws BadRealmException, NoSuchRealmException {
        return new FileRealm(mappedProperties.get(FileRealm.PARAM_KEYFILE));
    }

    public static LDAPRealm configureLDAPRealm(Map<String, String> mappedProperties) throws BadRealmException, NoSuchRealmException{
        LDAPRealm ldap = new LDAPRealm();
        
        Properties props = generateProperties(mappedProperties);
        ldap.init(props);
        
        return ldap;
    }
    
    private static Properties generateProperties(Map<String, String> mappedProperties) {
        Properties props = new Properties();
        for (Map.Entry<String, String> entrySet : mappedProperties.entrySet()) {
            props.put(entrySet.getKey(), entrySet.getValue());
        }
        return props;
    }
}
