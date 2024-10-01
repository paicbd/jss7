
package org.restcomm.protocols.ss7.m3ua.impl;

import javolution.util.FastList;

import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.m3ua.M3UAManagementEventListener;
import org.restcomm.protocols.ss7.m3ua.State;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSMState;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSMStateEventHandler;

/**
 *
 * @author amit bhayani
 *
 */
public abstract class SEHAsStateEnterActive implements FSMStateEventHandler {

    private static final Logger logger = Logger.getLogger(SEHAsStateEnterActive.class);

    private AsImpl asImpl;

    public SEHAsStateEnterActive(AsImpl asImpl) {
        this.asImpl = asImpl;
    }

    @Override
    public void onEvent(FSMState state) {
        // Call listener and indicate of state change only if not already done
        if (!this.asImpl.state.getName().equals(State.STATE_ACTIVE)) {
            AsState oldState = AsState.getState(this.asImpl.state.getName());
            this.asImpl.state = AsState.ACTIVE;

            FastList<M3UAManagementEventListener> managementEventListenersTmp = this.asImpl.m3UAManagementImpl.managementEventListeners;

            for (FastList.Node<M3UAManagementEventListener> n = managementEventListenersTmp.head(), end = managementEventListenersTmp
                    .tail(); (n = n.getNext()) != end;) {
                M3UAManagementEventListener m3uaManagementEventListener = n.getValue();
                try {
                    m3uaManagementEventListener.onAsActive(this.asImpl, oldState);
                } catch (Throwable ee) {
                    logger.error("Exception while invoking onAsActive", ee);
                }
            }
        }
    }

}
