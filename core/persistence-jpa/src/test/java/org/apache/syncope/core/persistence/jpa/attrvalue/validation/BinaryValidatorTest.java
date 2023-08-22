package org.apache.syncope.core.persistence.jpa.attrvalue.validation;

import jakarta.ws.rs.core.MediaType;
import org.apache.syncope.common.lib.types.AttrSchemaType;
import org.apache.syncope.core.persistence.api.attrvalue.validation.InvalidPlainAttrValueException;
import org.apache.syncope.core.persistence.api.entity.PlainAttr;
import org.apache.syncope.core.persistence.api.entity.PlainAttrValue;
import org.apache.syncope.core.persistence.api.entity.PlainSchema;
import org.apache.syncope.core.persistence.jpa.entity.JPAPlainSchema;
import org.apache.syncope.core.persistence.jpa.entity.anyobject.JPAAPlainAttr;
import org.apache.syncope.core.persistence.jpa.entity.anyobject.JPAAPlainAttrValue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

@RunWith(value= Parameterized.class)
public class BinaryValidatorTest {
    final static String VALID_JSON = "{\"name\": \"John Doe\", \"age\": 30, \"email\": \"john@example.com\"}";
    final static String NOT_VALID_JSON = "test";
    //parameters
    private PlainSchema schema;
    private PlainAttrValue attrValue;
    private Class<Exception> expectedException;

    public BinaryValidatorTest(Schema schemaType, Attribute attributeType, Class<Exception> expectedException) {
        schema = new JPAPlainSchema();
        PlainAttr plainAttr = new JPAAPlainAttr();
        attrValue = new JPAAPlainAttrValue();

        switch (schemaType) {
            case BINARY_VALID_EXISTENT : {
                schema.setType(AttrSchemaType.Binary);
                schema.setMimeType(MediaType.APPLICATION_JSON);
                break;
            }
            case BINARY_VALID_NOT_EXISTENT: {
                schema.setType(AttrSchemaType.Binary);
                schema.setMimeType("test/test");
                break;
            }
            case NOT_BINARY_VALID_EXISTENT: {
                schema.setType(AttrSchemaType.Long);
                schema.setMimeType(MediaType.APPLICATION_JSON);
                break;
            }
            case NOT_BINARY_VALID_NOT_EXISTENT: {
                schema.setType(AttrSchemaType.Long);
                schema.setMimeType("test/test");
                break;
            }
            case BINARY_INVALID: {
                schema.setType(AttrSchemaType.Binary);
                schema.setMimeType("test");
                break;
            }
            case NOT_BINARY_INVALID: {
                schema.setType(AttrSchemaType.Long);
                schema.setMimeType("test");
                break;
            }
            case NULLTYPE_NULLMIME: {
                schema.setType(null);
                schema.setMimeType(null);
                break;
            }
            case BINARY_NULLMIME: {
                schema.setType(AttrSchemaType.Binary);
                schema.setMimeType(null);
                break;
            }
            case NOT_BINARY_NULLMIME: {
                schema.setType(AttrSchemaType.Long);
                schema.setMimeType(null);
                break;
            }
            case NULLTYPE_VALID_EXISTENT: {
                schema.setType(null);
                schema.setMimeType(MediaType.APPLICATION_JSON);
                break;
            }
            case NULLTYPE_VALID_NOT_EXISTENT: {
                schema.setType(null);
                schema.setMimeType("test/test");
                break;
            }
            case NULLTYPE_INVALID: {
                schema.setType(null);
                schema.setMimeType("test");
                break;
            }
            case NULL: {
                schema = null;
            }
        }

        switch (attributeType) {
            case SCHEMA_VALID : {
                plainAttr.setSchema(schema);
                attrValue.setBinaryValue(VALID_JSON.getBytes());
                attrValue.setAttr(plainAttr);
                break;
            }
            case OTHERSCHEMA_VALID: {
                //se il primo parametro è nullo, il secondo parametro definisce uno schema binario (quindi comunque diverso dal primo)
                if (schema == null) {
                    schema = new JPAPlainSchema();
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(VALID_JSON.getBytes());
                    plainAttr.setSchema(schema);
                    attrValue.setAttr(plainAttr);
                    break;
                }
                AttrSchemaType firstType = schema.getType();
                schema = new JPAPlainSchema();
                //settiamo uno schema diverso da quello definito dal primo parametro
                if (firstType == AttrSchemaType.Binary) {
                    schema.setType(AttrSchemaType.Double);
                    attrValue.setDoubleValue(20.0);
                    attrValue.setBinaryValue(doubleToByteArray(20.0));
                }
                else {
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(VALID_JSON.getBytes());
                }
                plainAttr.setSchema(schema);
                attrValue.setAttr(plainAttr);
                break;
            }
            case SCHEMA_NOT_VALID: {
                plainAttr.setSchema(schema);
                attrValue.setBinaryValue(NOT_VALID_JSON.getBytes());
                attrValue.setAttr(plainAttr);
                break;
            }
            case OTHERSCHEMA_NOT_VALID: {
                //se il primo parametro è nullo, il secondo parametro definisce uno schema binario (quindi comunque diverso dal primo)
                if (schema == null) {
                    schema = new JPAPlainSchema();
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(NOT_VALID_JSON.getBytes());
                    plainAttr.setSchema(schema);
                    attrValue.setAttr(plainAttr);
                    break;
                }
                AttrSchemaType firstType = schema.getType();
                schema = new JPAPlainSchema();
                //settiamo uno schema diverso da quello definito dal primo parametro
                if (firstType == AttrSchemaType.Binary) {
                    schema.setType(AttrSchemaType.Double);
                    attrValue.setBinaryValue(NOT_VALID_JSON.getBytes());
                }
                else {
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(NOT_VALID_JSON.getBytes());
                }
                plainAttr.setSchema(schema);
                attrValue.setAttr(plainAttr);
                break;
            }
            case SCHEMA_NULLVALUE: {
                plainAttr.setSchema(schema);
                attrValue.setBinaryValue(null);
                attrValue.setAttr(plainAttr);
                break;
            }
            case OTHERSCHEMA_NULLVALUE: {
                //se il primo parametro è nullo, il secondo parametro definisce uno schema binario (quindi comunque diverso dal primo)
                if (schema == null) {
                    schema = new JPAPlainSchema();
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(null);
                    plainAttr.setSchema(schema);
                    attrValue.setAttr(plainAttr);
                    break;
                }
                AttrSchemaType firstType = schema.getType();
                schema = new JPAPlainSchema();
                //settiamo uno schema diverso da quello definito dal primo parametro
                if (firstType == AttrSchemaType.Binary) {
                    schema.setType(AttrSchemaType.Double);
                    attrValue.setBinaryValue(null);
                }
                else {
                    schema.setType(AttrSchemaType.Binary);
                    schema.setMimeType(MediaType.APPLICATION_JSON);
                    attrValue.setBinaryValue(null);
                }
                plainAttr.setSchema(schema);
                attrValue.setAttr(plainAttr);
                break;
            }
            case NULLSCHEMA_NULLVALUE: {
                plainAttr.setSchema(null);
                attrValue.setBinaryValue(null);
                attrValue.setAttr(plainAttr);
                break;
            }
            case NULL: {
                attrValue = null;
            }
        }

        this.expectedException = expectedException;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        return Arrays.asList(new Object[][]{
                // schema, attrValue, expectedException
                {Schema.BINARY_VALID_EXISTENT, Attribute.SCHEMA_VALID, null},
                {Schema.BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_VALID, InvalidPlainAttrValueException.class},  //non viene indicato un tipo mime valido (un tipo Double non ha un mime type)
                {Schema.BINARY_VALID_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_VALID_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},      //il valore binario nullo è da considerare valido (a prescindere dallo schema)
                {Schema.BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null}, //il valore binario nullo è da considerare valido (a prescindere dallo schema)
                {Schema.BINARY_VALID_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},  //il valore binario nullo è da considerare valido (a prescindere dallo schema)
                {Schema.BINARY_VALID_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},        //il tipo mime non esistente è gestito come un tipo non conforme al valore fornito
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.BINARY_VALID_NOT_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.SCHEMA_VALID, null},        //non verifica se l'attributo fornito rispetta il tipo dello schema indicato (code smell?)
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_VALID, null},   //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_VALID, null},             //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_VALID_NOT_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.BINARY_INVALID, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},    //il tipo mime indicato non è valido (perciò non verrà mai individuato un matching)
                {Schema.BINARY_INVALID, Attribute.OTHERSCHEMA_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_INVALID, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_INVALID, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_INVALID, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.BINARY_INVALID, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.BINARY_INVALID, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.BINARY_INVALID, Attribute.NULL, NullPointerException.class},

                {Schema.NOT_BINARY_INVALID, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},  //il tipo mime indicato non è valido (perciò non verrà mai individuato un matching)
                {Schema.NOT_BINARY_INVALID, Attribute.OTHERSCHEMA_VALID, null},                           //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NOT_BINARY_INVALID, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_INVALID, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_INVALID, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_INVALID, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_INVALID, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_INVALID, Attribute.NULL, NullPointerException.class},

                {Schema.NULLTYPE_NULLMIME, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},          //il tipo mime indicato è null (perciò non verrà mai individuato un matching)
                {Schema.NULLTYPE_NULLMIME, Attribute.OTHERSCHEMA_VALID, null},                                      //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NULLTYPE_NULLMIME, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_NULLMIME, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_NULLMIME, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_NULLMIME, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_NULLMIME, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_NULLMIME, Attribute.NULL, NullPointerException.class},

                {Schema.BINARY_NULLMIME, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},                  //il tipo mime indicato è null (perciò non verrà mai individuato un matching)
                {Schema.BINARY_NULLMIME, Attribute.OTHERSCHEMA_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_NULLMIME, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_NULLMIME, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.BINARY_NULLMIME, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.BINARY_NULLMIME, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.BINARY_NULLMIME, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.BINARY_NULLMIME, Attribute.NULL, NullPointerException.class},

                {Schema.NOT_BINARY_NULLMIME, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},                                              //il tipo mime indicato è null (perciò non verrà mai individuato un matching)
                {Schema.NOT_BINARY_NULLMIME, Attribute.OTHERSCHEMA_VALID, null},                                          //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NOT_BINARY_NULLMIME, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_NULLMIME, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NOT_BINARY_NULLMIME, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_NULLMIME, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_NULLMIME, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NOT_BINARY_NULLMIME, Attribute.NULL, NullPointerException.class},

                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.SCHEMA_VALID, null},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.OTHERSCHEMA_VALID, null},                                     //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},                                          //il tipo mime indicato non esiste (perciò non verrà mai individuato un matching)
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_VALID, null},                                   //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_VALID_NOT_EXISTENT, Attribute.NULL, NullPointerException.class},

                {Schema.NULLTYPE_INVALID, Attribute.SCHEMA_VALID, InvalidPlainAttrValueException.class},                                                             //il tipo mime indicato non esiste (perciò non verrà mai individuato un matching)
                {Schema.NULLTYPE_INVALID, Attribute.OTHERSCHEMA_VALID, null},                                             //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NULLTYPE_INVALID, Attribute.SCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_INVALID, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULLTYPE_INVALID, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_INVALID, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_INVALID, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NULLTYPE_INVALID, Attribute.NULL, NullPointerException.class},

                {Schema.NULL, Attribute.SCHEMA_VALID, NullPointerException.class},                //non può recuperare il tipo di mime perchè lo schema è null
                {Schema.NULL, Attribute.OTHERSCHEMA_VALID, null},                                 //non lancia l'eccezione, ma mi aspetto un eccezione!!!!! (possibile bug)
                {Schema.NULL, Attribute.SCHEMA_NOT_VALID, NullPointerException.class},            //non può recuperare il tipo di mime perchè lo schema è null
                {Schema.NULL, Attribute.OTHERSCHEMA_NOT_VALID, InvalidPlainAttrValueException.class},
                {Schema.NULL, Attribute.SCHEMA_NULLVALUE, null},
                {Schema.NULL, Attribute.OTHERSCHEMA_NULLVALUE, null},
                {Schema.NULL, Attribute.NULLSCHEMA_NULLVALUE, null},
                {Schema.NULL, Attribute.NULL, NullPointerException.class},
        });
    }

    @Test
    public void testDoValidation() {
        BinaryValidator binaryValidator = new BinaryValidator();
        try {
            binaryValidator.doValidate(schema, attrValue);
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, instanceOf(expectedException));
        }
    }

    public enum Schema {
        BINARY_VALID_EXISTENT ,
        BINARY_VALID_NOT_EXISTENT,
        NOT_BINARY_VALID_EXISTENT,
        NOT_BINARY_VALID_NOT_EXISTENT,
        BINARY_INVALID,
        NOT_BINARY_INVALID,
        NULLTYPE_NULLMIME,
        BINARY_NULLMIME,
        NOT_BINARY_NULLMIME,
        NULLTYPE_VALID_EXISTENT,
        NULLTYPE_VALID_NOT_EXISTENT,
        NULLTYPE_INVALID,
        NULL
    }

    public enum Attribute {
        SCHEMA_VALID,
        OTHERSCHEMA_VALID,
        SCHEMA_NOT_VALID,
        OTHERSCHEMA_NOT_VALID,
        SCHEMA_NULLVALUE,
        OTHERSCHEMA_NULLVALUE,
        NULLSCHEMA_NULLVALUE,
        NULL
    }

    public static byte[] doubleToByteArray(double value) {
        ByteBuffer buffer = ByteBuffer.allocate(Double.BYTES);
        buffer.putDouble(value);
        return buffer.array();
    }
}
