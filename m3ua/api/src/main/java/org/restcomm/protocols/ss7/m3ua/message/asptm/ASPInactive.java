package org.restcomm.protocols.ss7.m3ua.message.asptm;

import org.restcomm.protocols.ss7.m3ua.message.M3UAMessage;
import org.restcomm.protocols.ss7.m3ua.parameter.InfoString;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;

/**
 * The ASP Inactive message is sent by an ASP to indicate to a remote M3UA peer that it is no longer an active ASP to be used
 * from within a list of ASPs. The ASP Inactive message affects only the ASP state in the Routing Keys identified by the Routing
 * Contexts, if present.
 *
 * @author amit bhayani
 *
 */
public interface ASPInactive extends M3UAMessage {

    /**
     * The optional Routing Context parameter contains (a list of) integers indexing the Application Server traffic that the
     * sending ASP is configured/registered to receive.
     *
     * @return
     */
    RoutingContext getRoutingContext();

    void setRoutingContext(RoutingContext routingContext);

    InfoString getInfoString();

    void setInfoString(InfoString infoString);
}
