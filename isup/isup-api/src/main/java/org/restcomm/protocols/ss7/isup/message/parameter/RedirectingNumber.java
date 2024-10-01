package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:13:56:41 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 * @author sergey vetyutnev
 */
public interface RedirectingNumber extends CalledNumber, ISUPParameter {
    int _PARAMETER_CODE = 0x0B;

    // /**
    // * numbering plan indicator indicator value. See Q.763 - 3.9d
    // */
    // int _NPI_ISDN = 1;
    // /**
    // * numbering plan indicator indicator value. See Q.763 - 3.9d
    // */
    // int _NPI_DATA = 3;
    // /**
    // * numbering plan indicator indicator value. See Q.763 - 3.9d
    // */
    // int _NPI_TELEX = 4;
    //
    // /**
    // * address presentation restricted indicator indicator value. See Q.763 -
    // * 3.10e
    // */
    // int _APRI_ALLOWED = 0;
    //
    // /**
    // * address presentation restricted indicator indicator value. See Q.763 -
    // * 3.10e
    // */
    // int _APRI_RESTRICTED = 1;
    //
    // /**
    // * address presentation restricted indicator indicator value. See Q.763 -
    // * 3.10e
    // */
    // int _APRI_NOT_AVAILABLE = 2;
    //
    // /**
    // * address presentation restricted indicator indicator value. See Q.763 -
    // * 3.16d
    // */
    // int _APRI_SPARE = 3;
    //
    // public int getNumberingPlanIndicator();
    //
    // public void setNumberingPlanIndicator(int numberingPlanIndicator);
    //
    // public int getAddressRepresentationRestrictedIndicator();
    //
    // public void setAddressRepresentationRestrictedIndicator(int addressRepresentationREstrictedIndicator);

}
