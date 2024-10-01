
package org.restcomm.protocols.ss7.tools.simulator.tests.cap;

import java.util.Hashtable;

import org.restcomm.protocols.ss7.map.api.service.mobility.imei.EquipmentStatus;
import org.restcomm.protocols.ss7.tools.simulator.common.EnumeratedBase;

/**
 *
 * @author mnowa
 *
 */
public class IsupCauseIndicatorLocationType extends EnumeratedBase {

    private static final long serialVersionUID = 4473666813197137562L;

    private static Hashtable<String, Integer> stringMap = new Hashtable<String, Integer>();
    private static Hashtable<Integer, String> intMap = new Hashtable<Integer, String>();

    static {
        intMap.put(IsupCauseIndicatorLocation.user.getCode(), IsupCauseIndicatorLocation.user.toString());
        intMap.put(IsupCauseIndicatorLocation.privateNetworkServingLocalUser.getCode(), IsupCauseIndicatorLocation.privateNetworkServingLocalUser.toString());
        intMap.put(IsupCauseIndicatorLocation.publicNetworkServingLocalUser.getCode(), IsupCauseIndicatorLocation.publicNetworkServingLocalUser.toString());
        intMap.put(IsupCauseIndicatorLocation.transitNetwork.getCode(), IsupCauseIndicatorLocation.transitNetwork.toString());
        intMap.put(IsupCauseIndicatorLocation.publicNetworkServingRemoteUser.getCode(), IsupCauseIndicatorLocation.publicNetworkServingRemoteUser.toString());
        intMap.put(IsupCauseIndicatorLocation.privateNetworkServingRemoteUser.getCode(), IsupCauseIndicatorLocation.privateNetworkServingRemoteUser.toString());
        intMap.put(IsupCauseIndicatorLocation.internationalNetwork.getCode(), IsupCauseIndicatorLocation.internationalNetwork.toString());
        intMap.put(IsupCauseIndicatorLocation.networkBeyondIp.getCode(), IsupCauseIndicatorLocation.networkBeyondIp.toString());

        stringMap.put(IsupCauseIndicatorLocation.user.toString(), IsupCauseIndicatorLocation.user.getCode());
        stringMap.put(IsupCauseIndicatorLocation.privateNetworkServingLocalUser.toString(), IsupCauseIndicatorLocation.privateNetworkServingLocalUser.getCode());
        stringMap.put(IsupCauseIndicatorLocation.publicNetworkServingLocalUser.toString(), IsupCauseIndicatorLocation.publicNetworkServingLocalUser.getCode());
        stringMap.put(IsupCauseIndicatorLocation.transitNetwork.toString(), IsupCauseIndicatorLocation.transitNetwork.getCode());
        stringMap.put(IsupCauseIndicatorLocation.publicNetworkServingRemoteUser.toString(), IsupCauseIndicatorLocation.publicNetworkServingRemoteUser.getCode());
        stringMap.put(IsupCauseIndicatorLocation.privateNetworkServingRemoteUser.toString(), IsupCauseIndicatorLocation.privateNetworkServingRemoteUser.getCode());
        stringMap.put(IsupCauseIndicatorLocation.internationalNetwork.toString(), IsupCauseIndicatorLocation.internationalNetwork.getCode());
        stringMap.put(IsupCauseIndicatorLocation.networkBeyondIp.toString(), IsupCauseIndicatorLocation.networkBeyondIp.getCode());
    }

    public IsupCauseIndicatorLocationType() {
    }

    public IsupCauseIndicatorLocationType(int val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public IsupCauseIndicatorLocationType(Integer val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public IsupCauseIndicatorLocationType(String val) throws java.lang.IllegalArgumentException {
        super(val);
    }

    public static IsupCauseIndicatorLocationType createInstance(String s) {
        Integer i1 = doCreateInstance(s, stringMap, intMap);
        if (i1 == null)
            return new IsupCauseIndicatorLocationType(EquipmentStatus.whiteListed.getCode());
        else
            return new IsupCauseIndicatorLocationType(i1);
    }

    @Override
    protected Hashtable<Integer, String> getIntTable() {
        return intMap;
    }

    @Override
    protected Hashtable<String, Integer> getStringTable() {
        return stringMap;
    }
}
