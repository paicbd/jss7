
package org.restcomm.protocols.ss7.tcapAnsi.tc.dialog.events;

import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.ApplicationContext;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.Confidentiality;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.SecurityContext;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.UserInformation;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.EventType;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCQueryRequest;

/**
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public class TCQueryRequestImpl extends DialogRequestImpl implements TCQueryRequest {

    private SccpAddress originatingAddress, destinationAddress;

    // fields
    private ApplicationContext applicationContextName;
    private UserInformation userInformation;
    private boolean dialogTermitationPermission;
    private SecurityContext securityContext;
    private Confidentiality confidentiality;

    TCQueryRequestImpl(boolean dialogTermitationPermission) {
        super(dialogTermitationPermission ? EventType.QueryWithPerm : EventType.QueryWithoutPerm);

        this.dialogTermitationPermission = dialogTermitationPermission;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# getApplicationContextName()
     */
    public ApplicationContext getApplicationContextName() {
        return applicationContextName;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# getDestinationAddress()
     */
    public SccpAddress getDestinationAddress() {

        return this.destinationAddress;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# getOriginatingAddress()
     */
    public SccpAddress getOriginatingAddress() {

        return this.originatingAddress;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# getUserInformation()
     */
    public UserInformation getUserInformation() {

        return this.userInformation;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# setApplicationContextName
     * (org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName)
     */
    public void setApplicationContextName(ApplicationContext acn) {
        this.applicationContextName = acn;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# setDestinationAddress
     * (org.restcomm.protocols.ss7.sccp.parameter.SccpAddress)
     */
    public void setDestinationAddress(SccpAddress dest) {
        this.destinationAddress = dest;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest# setOriginatingAddress
     * (org.restcomm.protocols.ss7.sccp.parameter.SccpAddress)
     */
    public void setOriginatingAddress(SccpAddress dest) {
        this.originatingAddress = dest;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.api.tc.dialog.events.TCBeginRequest#
     * setUserInformation(org.restcomm.protocols.ss7.tcap.asn.UserInformation)
     */
    public void setUserInformation(UserInformation ui) {
        this.userInformation = ui;

    }

    public void setReturnMessageOnError(boolean val) {
        returnMessageOnError = val;
    }

    public boolean getReturnMessageOnError() {
        return returnMessageOnError;
    }

    @Override
    public boolean getDialogTermitationPermission() {
        return dialogTermitationPermission;
    }

    @Override
    public void setDialogTermitationPermission(boolean dialogTermitationPermission) {
        this.dialogTermitationPermission = dialogTermitationPermission;
        if (dialogTermitationPermission)
            this.type = EventType.QueryWithPerm;
        else
            this.type = EventType.QueryWithoutPerm;
    }

    @Override
    public SecurityContext getSecurityContext() {
        return securityContext;
    }

    @Override
    public void setSecurityContext(SecurityContext val) {
        securityContext = val;
    }

    @Override
    public Confidentiality getConfidentiality() {
        return confidentiality;
    }

    @Override
    public void setConfidentiality(Confidentiality val) {
        confidentiality = val;
    }

}
