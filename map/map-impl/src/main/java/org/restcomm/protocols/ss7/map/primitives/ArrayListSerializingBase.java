
package org.restcomm.protocols.ss7.map.primitives;

import java.util.ArrayList;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class ArrayListSerializingBase<T> {

    private ArrayList<T> data = new ArrayList<T>();
    private String elementName;
    private Class<? extends T> classDef;

    public ArrayListSerializingBase(String elementName, Class<? extends T> classDef, ArrayList<T> data) {
        this.data = data;
        this.classDef = classDef;
        this.elementName = elementName;
    }

    public ArrayListSerializingBase(String elementName, Class<? extends T> classDef) {
        this.elementName = elementName;
        this.classDef = classDef;
    }

    public ArrayList<T> getData() {
        return this.data;
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<ArrayListSerializingBase> ARRAY_LIST_SERIALIZING_BASE_XML = new XMLFormat<ArrayListSerializingBase>(
            ArrayListSerializingBase.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, ArrayListSerializingBase data) throws XMLStreamException {
            data.data.clear();

            while (xml.hasNext()) {
                String localName = xml.getStreamReader().getLocalName().toString();
                if (localName.equals(data.elementName)) {
                    data.data.add(xml.get(data.elementName, data.classDef));
                } else
                    throw new XMLStreamException("Only <" + data.elementName + "> elements are allowed in this list. Found: " + localName);
            }
        }

        @Override
        public void write(ArrayListSerializingBase data, javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {
            if (data.data != null && data.data.size() > 0) {
                for (int i1 = 0; i1 < data.data.size(); i1++) {
                    Object pe = data.data.get(i1);
                    if (pe != null)
                        xml.add(pe, data.elementName, data.classDef);
                }
            }
        }
    };

}
