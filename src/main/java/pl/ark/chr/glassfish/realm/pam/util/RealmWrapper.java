package pl.ark.chr.glassfish.realm.pam.util;

import com.sun.enterprise.security.auth.realm.Realm;

/**
 *
 * @author Arek
 */
public class RealmWrapper {
    
    private Realm realm;
    private String controlValue;

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getControlValue() {
        return controlValue;
    }

    public void setControlValue(String controlValue) {
        this.controlValue = controlValue;
    }
}
