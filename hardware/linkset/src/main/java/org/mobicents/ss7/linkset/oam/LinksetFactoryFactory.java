package org.mobicents.ss7.linkset.oam;

import javolution.util.FastMap;
import javolution.xml.XMLBinding;

/**
 * <p>
 * Factory class that holds map of {@link LinksetFactory}.
 * </p>
 *
 * @author amit bhayani
 *
 */
public class LinksetFactoryFactory {

    private FastMap<String, LinksetFactory> linksetFactories = new FastMap<String, LinksetFactory>();

    /**
     * Call back method to add new {@link LinksetFactory}
     *
     * @param factory
     */
    public void addFactory(LinksetFactory factory) {
        linksetFactories.put(factory.getName(), factory);
    }

    /**
     * Call back method to remove existing {@link LinksetFactory}
     *
     * @param factory
     */
    public void removeFactory(LinksetFactory factory) {
        linksetFactories.remove(factory);
    }

    public void loadBinding(XMLBinding binding) {
        FastMap.Entry<String, LinksetFactory> e = this.linksetFactories.head();
        FastMap.Entry<String, LinksetFactory> end = this.linksetFactories.tail();
        for (; (e = e.getNext()) != end;) {
            LinksetFactory linksetFactory = e.getValue();
            if (linksetFactory.getLinkName() != null)
                binding.setAlias(linksetFactory.getLinkClass(), linksetFactory.getLinkName());

            if (linksetFactory.getLinksetName() != null)
                binding.setAlias(linksetFactory.getLinksetClass(), linksetFactory.getLinksetName());
        }
    }

    /**
     * Create a new {@link Linkset} depending on the options passed.
     *
     * @param options
     * @return
     * @throws Exception
     */
    public Linkset createLinkset(String[] options) throws Exception {
        if (options == null) {
            throw new Exception(LinkOAMMessages.INVALID_COMMAND);
        }

        // The expected command is "linkset create <likset-type> <options>"
        // Expect atleast length to 3
        if (options.length < 3) {
            throw new Exception(LinkOAMMessages.INVALID_COMMAND);
        }

        String type = options[2];

        if (type == null) {
            throw new Exception(LinkOAMMessages.INVALID_COMMAND);
        }

        LinksetFactory linksetFactory = linksetFactories.get(type);

        if (linksetFactory == null) {
            throw new Exception(LinkOAMMessages.INVALID_COMMAND);
        }
        return linksetFactory.createLinkset(options);
    }

    public FastMap<String, LinksetFactory> getLinksetFactories() {
        return linksetFactories;
    }
}