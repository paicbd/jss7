package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:11:52:57 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface CalledPartyNumber extends NAINumber, ISUPParameter {
    int _PARAMETER_CODE = 0x04;

    /**
     * numbering plan indicator indicator value. See Q.763 - 3.9d
     */
    int _NPI_ISDN = 1;
    /**
     * numbering plan indicator indicator value. See Q.763 - 3.9d
     */
    int _NPI_DATA = 3;
    /**
     * numbering plan indicator indicator value. See Q.763 - 3.9d
     */
    int _NPI_TELEX = 4;

    /**
     * internal network number indicator indicator value. See Q.763 - 3.9c
     */
    int _INN_ROUTING_ALLOWED = 0;
    /**
     * internal network number indicator indicator value. See Q.763 - 3.9c
     *
     */
    int _INN_ROUTING_NOT_ALLOWED = 1;

    // Extension to NAI

    /**
     * nature of address indicator value. See Q.763 - 3.46b network routing number in national (significant) number format
     * (national use)
     */
    int _NAI_NRNINNF = 6;

    /**
     * nature of address indicator value. See Q.763 - 3.46b network routing number in network-specific number format (national
     * use)
     */
    int _NAI_NRNINSNF = 7;
    /**
     * nature of address indicator value. See Q.763 - 3.46b reserved for network routing number concatenated with Called
     * Directory Number (national use)
     */
    int _NAI_RNRNCWCDN = 8;

    int getNumberingPlanIndicator();

    void setNumberingPlanIndicator(int numberingPlanIndicator);

    int getInternalNetworkNumberIndicator();

    void setInternalNetworkNumberIndicator(int internalNetworkNumberIndicator);

}
