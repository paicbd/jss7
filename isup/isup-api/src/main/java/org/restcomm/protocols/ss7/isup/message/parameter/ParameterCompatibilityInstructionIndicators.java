package org.restcomm.protocols.ss7.isup.message.parameter;

import java.io.Serializable;

/**
 * Start time:13:18:50 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface ParameterCompatibilityInstructionIndicators extends Serializable{

    /**
     * See Q.763 3.41 Transit at intermediate exchange indicator : transit interpretation
     */
    boolean _TI_TRANSIT_INTEPRETATION = false;
    /**
     * See Q.763 3.41 Transit at intermediate exchange indicator :
     */
    boolean _TI_ETE_INTEPRETATION = true;
    /**
     * See Q.763 3.41 Release call indicator : do not release
     */
    boolean _RCI_DO_NOT_RELEASE = false;
    /**
     * See Q.763 3.41 Release call indicator : reelase call
     */
    boolean _RCI_RELEASE = true;
    /**
     * See Q.763 3.41 Send notification indicator: do not send notification
     */
    boolean _SNDI_DO_NOT_SEND_NOTIFIACTION = false;
    /**
     * See Q.763 3.41 Send notification indicator: send notification
     */
    boolean _SNDI_SEND_NOTIFIACTION = true;
    /**
     * See Q.763 3.41 Discard message indicator : do not discard message (pass on)
     */
    boolean _DMI_DO_NOT_DISCARD = false;
    /**
     * See Q.763 3.41 Discard message indicator : discard message
     */
    boolean _DMI_DISCARD = true;

    /**
     * See Q.763 3.41 Discard parameter indicator : do not discard parameter (pass on)
     */
    boolean _DPI_DO_NOT_DISCARD = false;
    /**
     * See Q.763 3.41 Discard parameter indicator : discard parameter
     */
    boolean _DPI_INDICATOR_DISCARD = true;

    /**
     * See Q.763 3.41 Pass on not possible indicator : release call
     */
    int _PONPI_RELEASE_CALL = 0;

    /**
     * See Q.763 3.41 Pass on not possible indicator : discard message
     */
    int _PONPI_DISCARD_MESSAGE = 1;

    /**
     * See Q.763 3.41 Pass on not possible indicator : discard parameter
     */
    int _PONPI_DISCARD_PARAMETER = 2;

    /**
     * See Q.763 3.41 Broadband/narrowband interworking indicator : pass on
     */
    int _BII_PASS_ON = 0;

    /**
     * See Q.763 3.41 Broadband/narrowband interworking indicator : discard message
     */
    int _BII_DISCARD_MESSAGE = 1;

    /**
     * See Q.763 3.41 Broadband/narrowband interworking indicator : release call
     */
    int _BII_RELEASE_CALL = 2;

    /**
     * See Q.763 3.41 Broadband/narrowband interworking indicator : discard parameter
     */
    int _BII_DISCARD_PARAMETER = 3;

    void setParamerterCode(byte code);

    byte getParameterCode();

    boolean isTransitAtIntermediateExchangeIndicator();

    void setTransitAtIntermediateExchangeIndicator(boolean transitAtIntermediateExchangeIndicator);

    boolean isReleaseCallIndicator();

    void setReleaseCallIndicator(boolean releaseCallindicator);

    boolean isSendNotificationIndicator();

    void setSendNotificationIndicator(boolean sendNotificationIndicator);

    boolean isDiscardMessageIndicator();

    void setDiscardMessageIndicator(boolean discardMessageIndicator);

    boolean isDiscardParameterIndicator();

    void setDiscardParameterIndicator(boolean discardParameterIndicator);

    int getPassOnNotPossibleIndicator();

    void setPassOnNotPossibleIndicator(int passOnNotPossibleIndicator2);

    int getBandInterworkingIndicator();

    void setBandInterworkingIndicator(int bandInterworkingIndicator);

    boolean isSecondOctetPresent();

    void setSecondOctetPresent(boolean secondOctetPresenet);

    byte[] getRaw();

    void setRaw(byte[] raw);

    boolean isUseAsRaw();

    void setUseAsRaw(boolean useAsRaw);

}
