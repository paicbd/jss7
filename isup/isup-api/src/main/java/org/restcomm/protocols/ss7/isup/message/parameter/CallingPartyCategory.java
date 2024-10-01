package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:11:56:46 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface CallingPartyCategory extends ISUPParameter {
    int _PARAMETER_CODE = 0x09;

    /**
     * See Q.763 3.11
     */
    byte _CATEGORY_UNKNOWN = 0;

    /**
     * See Q.763 3.11 operator, language French
     */
    byte _CATEGORY_OL_FRENCH = 1;

    /**
     * See Q.763 3.11 operator, language English
     */
    byte _CATEGORY_OL_ENGLISH = 2;

    /**
     * See Q.763 3.11 operator, language German
     */
    byte _CATEGORY_OL_GERMAN = 3;

    /**
     * See Q.763 3.11 operator, language Russian
     */
    byte _CATEGORY_OL_RUSSIAN = 4;

    /**
     * See Q.763 3.11 operator, language Spanish
     */
    byte _CATEGORY_OL_SPANISH = 5;

    byte _OPERATOR_NATIONAL = 9;
    byte _ORDINARY_SUBSCRIBER = 10;
    byte _PRIORITY_SUBSCRIBER = 11;
    byte _DATA_CALL = 12;
    byte _TEST_CALL = 13;
    byte _PAYPHONE = 14;

    byte getCallingPartyCategory();

    void setCallingPartyCategory(byte callingPartyCategory);
}
