package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.CalledDirectoryNumber;

/**
 * Start time:16:42:16 2009-04-05<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class CalledDirectoryNumberImpl extends AbstractNAINumber implements CalledDirectoryNumber {

    protected int numberingPlanIndicator;

    protected int internalNetworkNumberIndicator;

    /**
     * @param representation
     */
    public CalledDirectoryNumberImpl(byte[] representation) throws ParameterException {
        super(representation);

        getNumberingPlanIndicator();
    }

    /**
     *
     * @param bis
     */
    public CalledDirectoryNumberImpl(ByteArrayInputStream bis) throws ParameterException {
        super(bis);

    }

    public CalledDirectoryNumberImpl() {
        super();

    }

    public CalledDirectoryNumberImpl(int natureOfAddresIndicator, String address, int numberingPlanIndicator,
            int internalNetworkNumberIndicator) {
        super(natureOfAddresIndicator, address);
        this.numberingPlanIndicator = numberingPlanIndicator;
        this.internalNetworkNumberIndicator = internalNetworkNumberIndicator;
    }

    public int decodeBody(ByteArrayInputStream bis) throws IllegalArgumentException {
        if (bis.available() == 0) {
            throw new IllegalArgumentException("No more data to read.");
        }
        int b = bis.read() & 0xff;

        this.internalNetworkNumberIndicator = (b & 0x80) >> 7;
        this.numberingPlanIndicator = (b >> 4) & 0x07;

        return 1;
    }

    public int encodeBody(ByteArrayOutputStream bos) {
        int c = (this.numberingPlanIndicator & 0x07) << 4;
        c |= (this.internalNetworkNumberIndicator << 7);
        bos.write(c);
        return 1;
    }

    public int getNumberingPlanIndicator() {

        return this.numberingPlanIndicator;
    }

    public void setNumberingPlanIndicator(int numberingPlanIndicator) {

        this.numberingPlanIndicator = numberingPlanIndicator;

    }

    public int getInternalNetworkNumberIndicator() {
        return internalNetworkNumberIndicator;
    }

    public void setInternalNetworkNumberIndicator(int internalNetworkNumberIndicator) {
        this.internalNetworkNumberIndicator = internalNetworkNumberIndicator;
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
