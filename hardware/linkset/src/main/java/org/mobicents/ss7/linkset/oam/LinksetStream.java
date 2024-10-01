package org.mobicents.ss7.linkset.oam;

import java.io.IOException;

import org.mobicents.protocols.stream.api.Stream;

/**
 * The stream for underlying {@link Linkset}.
 *
 * @author amit bhayani
 *
 */
public abstract class LinksetStream implements Stream {

    protected LinksetSelectorKey selectorKey = null;

    /**
     * Poll the respective stream for readiness
     *
     * @param operation
     * @param timeout
     * @return
     */
    public abstract boolean poll(int operation, int timeout);

    /**
     * Get the name of the Stream.
     *
     * @return
     */
    public abstract String getName();

    public abstract int write(byte[] paramArrayOfByte) throws IOException;

    public abstract int read(byte[] paramArrayOfByte) throws IOException;

}