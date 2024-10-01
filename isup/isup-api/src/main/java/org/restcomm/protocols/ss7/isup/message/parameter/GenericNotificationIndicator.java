package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:13:04:54 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface GenericNotificationIndicator extends ISUPParameter {
    int _PARAMETER_CODE = 0x2C;

    /**
     * See Q.763 3.25 Notification indicator : user suspended
     */
    int _NI_USER_SUSPENDED = 0;

    /**
     * See Q.763 3.25 Notification indicator : user resumed
     */
    int _NI_USER_RESUMED = 1;

    /**
     * See Q.763 3.25 Notification indicator : bearer service change
     */
    int _NI_BEARER_SERVICE_CHANGE = 2;
    /**
     * See Q.763 3.25 Notification indicator : discriminator for extension to ASN.1
     */
    int _NI_DISCRIMINATOR_FOR_EXTENSION_TO_ASN1 = 3;

    /**
     * See Q.763 3.25 Notification indicator : conference established
     */
    int _NI_CONFERENCE_ESTABILISHED = 0x42;

    /**
     * See Q.763 3.25 Notification indicator : conference disconnected
     */
    int _NI_CONFERENCE_DISCONNECTED = 0x43;

    /**
     * See Q.763 3.25 Notification indicator : other party added
     */
    int _NI_OTHER_PARTY_ADDED = 0x44;
    /**
     * See Q.763 3.25 Notification indicator : isolated
     */
    int _NI_ISOLATED = 0x45;
    /**
     * See Q.763 3.25 Notification indicator : reattached
     */
    int _NI_REATTACHED = 0x46;

    /**
     * See Q.763 3.25 Notification indicator : other party isolated
     */
    int _NI_OTHER_PARTY_ISOLATED = 0x47;

    /**
     * See Q.763 3.25 Notification indicator : other party reattached
     */
    int _NI_OTHER_PARTY_REATTACHED = 0x48;
    /**
     * See Q.763 3.25 Notification indicator : other party split
     */
    int _NI_OTHER_PARTY_SPLIT = 0x49;
    /**
     * See Q.763 3.25 Notification indicator : other party disconnected
     */
    int _NI_OTHER_PARTY_DISCONNECTED = 0x4A;

    /**
     * See Q.763 3.25 Notification indicator : conference floating
     */
    int _NI_CONFERENCE_FLOATING = 0x4B;

    /**
     * See Q.763 3.25 Notification indicator : call is a waiting call
     */
    int _NI_CALL_IS_AWAITING = 0xC0;

    /**
     * See Q.763 3.25 Notification indicator : diversion activated (used in DSS1)
     */
    int _NI_DIVERSION_ACTIVATED = 0x68;

    /**
     * See Q.763 3.25 Notification indicator : call transfer, alerting
     */
    int _NI_CALL_TRANSFER_ALERTING = 0x69;

    /**
     * See Q.763 3.25 Notification indicator : call transfer, active
     */
    int _NI_CALL_TRANSFER_ACTIVE = 0x6A;

    /**
     * See Q.763 3.25 Notification indicator : remote hold
     */
    int _NI_REMOTE_HOLD = 0x79;

    /**
     * See Q.763 3.25 Notification indicator : remote retrieval
     */
    int _NI_REMOTE_RETRIEVAL = 0x8A;

    /**
     * See Q.763 3.25 Notification indicator : call is diverting
     */
    int _NI_RCID = 0x8B;

    int[] getNotificationIndicator();

    void setNotificationIndicator(int[] notificationIndicator) throws IllegalArgumentException;
}
