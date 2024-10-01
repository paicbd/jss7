package org.restcomm.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.message.parameter.GVNSUserGroup;

/**
 * Start time:13:58:48 2009-04-04<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class GVNSUserGroupImpl extends AbstractNumber implements GVNSUserGroup {

    // FIXME: shoudl we add max octets ?
    private int gugLengthIndicator;

    public GVNSUserGroupImpl() {

    }

    public GVNSUserGroupImpl(byte[] representation) throws ParameterException {
        super(representation);

    }

    public GVNSUserGroupImpl(ByteArrayInputStream bis) throws ParameterException {
        super(bis);

    }

    public GVNSUserGroupImpl(String address) {
        super(address);

    }

    public int decode(byte[] b) throws ParameterException {
        return super.decode(b);
    }

    public byte[] encode() throws ParameterException {
        return super.encode();
    }

    public int decodeHeader(ByteArrayInputStream bis) throws IllegalArgumentException {
        int b = bis.read() & 0xff;

        this.oddFlag = (b & 0x80) >> 7;
        this.gugLengthIndicator = b & 0x0F;
        return 1;
    }

    public int encodeHeader(ByteArrayOutputStream bos) {
        int b = 0;
        // Even is 000000000 == 0
        boolean isOdd = this.oddFlag == _FLAG_ODD;
        if (isOdd)
            b |= 0x80;
        b |= this.gugLengthIndicator & 0x0F;
        bos.write(b);
        return 1;
    }

    public int decodeBody(ByteArrayInputStream bis) throws IllegalArgumentException {

        return 0;
    }

    public int encodeBody(ByteArrayOutputStream bos) {

        return 0;
    }

    public int getGugLengthIndicator() {
        return gugLengthIndicator;
    }

    public int decodeDigits(ByteArrayInputStream bis) throws IllegalArgumentException, ParameterException {
        return super.decodeDigits(bis, this.gugLengthIndicator);
    }

    public void setAddress(String address) {
        // TODO Auto-generated method stub
        super.setAddress(address);
        int l = super.address.length();
        this.gugLengthIndicator = l / 2 + l % 2;
        if (gugLengthIndicator > 8) {
            throw new IllegalArgumentException("Maximum octets for this parameter in digits part is 8.");
            // FIXME: add check for digit (max 7 ?)
        }
    }

    public int getCode() {

        return _PARAMETER_CODE;
    }
}
