package com.fasterxml.jackson.databind.jsontype.vld;

import java.util.*;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import com.fasterxml.jackson.databind.BaseMapTest;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator.Validity;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

import static org.junit.Assert.assertArrayEquals;

/**
 * Tests for [CVE-2026-110879]: classes named as type parameters of a generic
 * type id must pass the same checks as classes named directly as a type id
 * (for base type {@code Object}), regardless of which declared type parameter
 * they bind to and regardless of the outer type having been approved.
 */
public class GenericTypeIdParameterValidationTest extends BaseMapTest
{
    static final List<String> INSTANTIATIONS = new ArrayList<>();

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public interface Msg { }

    public static class Env<T> implements Msg {
        public T payload;
    }

    public static class PlainMsg implements Msg {
        public String text;
    }

    /** Stand-in "gadget" type: never allow-listed */
    public static class Gadget {
        public Gadget() {
            INSTANTIATIONS.add("Gadget()");
        }

        // Single-String constructor: usable as Map key via key deserializer
        public Gadget(String key) {
            INSTANTIATIONS.add("Gadget(" + key + ")");
        }

        public void setCmd(String cmd) {
            INSTANTIATIONS.add("setCmd(" + cmd + ")");
        }
    }

    /** Abstract, but still deserializable "gadget" type */
    @JsonDeserialize(as = AbstractGadgetImpl.class)
    public static abstract class AbstractGadget {
        public void setCmd(String cmd) {
            INSTANTIATIONS.add("setCmd(" + cmd + ")");
        }
    }

    public static class AbstractGadgetImpl extends AbstractGadget {
        public AbstractGadgetImpl() {
            INSTANTIATIONS.add("AbstractGadgetImpl()");
        }
    }

    /** Allow-listed (by some tests) bean type */
    public static class SafeBean {
        public String data;
    }

    public enum Color { RED, GREEN }

    static class MsgWrapper {
        public Msg msg;
    }

    static class MinimalClassWrapper {
        @JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)
        public Iterable<String> values;
    }

    static final class StringMapWrapper {
        public Map<String, String> map;
    }

    static final class ArrayMapWrapper {
        public Map<String, Object> map;
    }

    static class SerializableWrapper {
        @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
        public java.io.Serializable value;
    }

    public static class SubBean extends SafeBean {
        public int extra;
    }

    public static final class FinalSubBean extends SafeBean {
        public int extra;
    }

    static final class BeanArrayWrapper {
        public SafeBean[] beans;
    }

    static class ObjectValueWrapper {
        @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
        public Object value;
    }

    static final class ObjectArrayWrapper {
        public Object[] values;
    }

    static final class EnumContainersWrapper {
        public EnumMap<Color, String> enumMap;
        public EnumSet<Color> enumSet;
    }

    private final String ENV = Env.class.getName();
    private final String GADGET = Gadget.class.getName();
    private final String ABSTRACT_GADGET = AbstractGadget.class.getName();

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        INSTANTIATIONS.clear();
    }

    /*
    /**********************************************************************
    /* Default (base-type limiting) validator, annotation-based typing
    /**********************************************************************
     */

    private ObjectMapper blockingMapper() {
        return jsonMapperBuilder()
                .enable(MapperFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES)
                .build();
    }

    public void testDirectGadgetIsNotASubtype() throws Exception
    {
        try {
            blockingMapper().readValue(msgJson(GADGET, "\"cmd\":\"x\""),
                    MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "Not a subtype");
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    public void testGadgetAsTypeParameterRejected() throws Exception
    {
        try {
            blockingMapper().readValue(msgJson(ENV + "<" + GADGET + ">",
                    "\"payload\":{\"cmd\":\"x\"}"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    public void testNestedGadgetAsTypeParameterRejected() throws Exception
    {
        try {
            blockingMapper().readValue(
                    msgJson(ENV + "<java.util.ArrayList<" + GADGET + ">>",
                            "\"payload\":[{},{},{}]"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    public void testSafeTypeParametersAccepted() throws Exception
    {
        ObjectMapper mapper = blockingMapper();
        MsgWrapper w = mapper.readValue(msgJson(ENV, "\"payload\":\"a\""), MsgWrapper.class);
        assertEquals("a", ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<java.lang.String>", "\"payload\":\"b\""),
                MsgWrapper.class);
        assertEquals("b", ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<java.lang.Integer>", "\"payload\":3"),
                MsgWrapper.class);
        assertEquals(Integer.valueOf(3), ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<" + Color.class.getName() + ">",
                "\"payload\":\"GREEN\""), MsgWrapper.class);
        assertEquals(Color.GREEN, ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<java.lang.Object>", "\"payload\":\"c\""),
                MsgWrapper.class);
        assertEquals("c", ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<java.math.BigDecimal>", "\"payload\":1.25"),
                MsgWrapper.class);
        assertEquals(new java.math.BigDecimal("1.25"), ((Env<?>) w.msg).payload);

        w = mapper.readValue(msgJson(ENV + "<java.math.BigInteger>", "\"payload\":7"),
                MsgWrapper.class);
        assertEquals(java.math.BigInteger.valueOf(7), ((Env<?>) w.msg).payload);

        final UUID uuid = UUID.randomUUID();
        w = mapper.readValue(msgJson(ENV + "<java.util.UUID>", "\"payload\":\"" + uuid + "\""),
                MsgWrapper.class);
        assertEquals(uuid, ((Env<?>) w.msg).payload);
    }

    /*
    /**********************************************************************
    /* Approval of outer base type must not approve type parameters
    /**********************************************************************
     */

    public void testAllowedBaseTypeDoesNotApproveTypeParameters() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Msg.class)
                        .build())
                .build();
        // Approved base type: direct subtypes and safe type parameters fine
        MsgWrapper w = mapper.readValue(msgJson(PlainMsg.class.getName(), "\"text\":\"x\""),
                MsgWrapper.class);
        assertEquals(PlainMsg.class, w.msg.getClass());
        w = mapper.readValue(msgJson(ENV + "<java.lang.String>", "\"payload\":\"b\""),
                MsgWrapper.class);
        assertEquals("b", ((Env<?>) w.msg).payload);

        try {
            mapper.readValue(msgJson(ENV + "<" + GADGET + ">",
                    "\"payload\":{\"cmd\":\"x\"}"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            // Should name the configured validator, not the internal wrapper
            verifyException(e, BasicPolymorphicTypeValidator.class.getName());
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        try {
            mapper.readValue(msgJson(ENV + "<" + SafeBean.class.getName() + ">",
                    "\"payload\":{\"data\":\"x\"}"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, SafeBean.class.getName());
        }
    }

    // Type parameter that is subtype of polymorphic base type: same checks as direct type id
    public void testBaseSubtypeAsTypeParameterAccepted() throws Exception
    {
        final String plainMsgId = ENV + "<" + PlainMsg.class.getName() + ">";
        // (payload is a `Msg` so has type id of its own)
        final String json = msgJson(plainMsgId, "\"payload\":{\"@class\":\""
                + PlainMsg.class.getName() + "\",\"text\":\"x\"}");
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Msg.class)
                        .build())
                .build();
        MsgWrapper w = mapper.readValue(json, MsgWrapper.class);
        assertEquals("x", ((PlainMsg) ((Env<?>) w.msg).payload).text);

        w = blockingMapper().readValue(json, MsgWrapper.class);
        assertEquals("x", ((PlainMsg) ((Env<?>) w.msg).payload).text);
    }

    public void testAllowListedTypeParameterAccepted() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Msg.class)
                        .allowIfSubType(SafeBean.class)
                        .build())
                .build();
        MsgWrapper w = mapper.readValue(msgJson(ENV + "<" + SafeBean.class.getName() + ">",
                "\"payload\":{\"data\":\"x\"}"), MsgWrapper.class);
        assertEquals("x", ((SafeBean) ((Env<?>) w.msg).payload).data);
    }

    public void testMinimalClassTypeParameterRejected() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Iterable.class)
                        .build())
                .build();
        // (JSON Arrays use wrapper-array type id inclusion)
        MinimalClassWrapper w = mapper.readValue(aposToQuotes(
                "{'values':['java.util.ArrayList<java.lang.String>',['a']]}"),
                MinimalClassWrapper.class);
        assertEquals(Arrays.asList("a"), w.values);
        try {
            mapper.readValue(aposToQuotes(
                    "{'values':['java.util.ArrayList<" + GADGET + ">',[{}]]}"),
                    MinimalClassWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    /*
    /**********************************************************************
    /* Default typing with outer-base rule, Map key
    /**********************************************************************
     */

    private ObjectMapper mapDefaultTypingMapper() {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Map.class)
                .build();
        return jsonMapperBuilder()
                .activateDefaultTyping(ptv, DefaultTyping.NON_FINAL)
                .build();
    }

    public void testDefaultTypingMapKeyGadgetRejected() throws Exception
    {
        ObjectMapper mapper = mapDefaultTypingMapper();
        try {
            mapper.readValue(aposToQuotes("{'map':['java.util.HashMap<" + GADGET
                    + ",java.lang.String>',{'attacker-chosen':'x'}]}"),
                    StringMapWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    public void testDefaultTypingCompatibleMapAccepted() throws Exception
    {
        ObjectMapper mapper = mapDefaultTypingMapper();
        StringMapWrapper input = new StringMapWrapper();
        input.map = new HashMap<>();
        input.map.put("a", "b");
        String json = mapper.writeValueAsString(input);
        assertEquals(input.map, mapper.readValue(json, StringMapWrapper.class).map);

        StringMapWrapper w = mapper.readValue(aposToQuotes(
                "{'map':['java.util.HashMap<java.lang.String,java.lang.String>',{'c':'d'}]}"),
                StringMapWrapper.class);
        assertEquals(Collections.singletonMap("c", "d"), w.map);
    }

    // Arrays are not gadgets by themselves: only their element type is validated
    public void testDefaultTypingArrayTypeParameters() throws Exception
    {
        ObjectMapper mapper = mapDefaultTypingMapper();
        ArrayMapWrapper w = mapper.readValue(aposToQuotes(
                "{'map':['java.util.HashMap<java.lang.String,[Ljava.lang.String;>',{'k':['a','b']}]}"),
                ArrayMapWrapper.class);
        assertArrayEquals(new String[] { "a", "b" }, (String[]) w.map.get("k"));

        w = mapper.readValue(aposToQuotes("{'map':['java.util.HashMap<java.lang.String,[I>',{'k':[1,2]}]}"),
                ArrayMapWrapper.class);
        assertArrayEquals(new int[] { 1, 2 }, (int[]) w.map.get("k"));

        w = mapper.readValue(aposToQuotes("{'map':['java.util.HashMap<java.lang.String,[L"
                + Color.class.getName() + ";>',{'k':['RED']}]}"),
                ArrayMapWrapper.class);
        assertArrayEquals(new Color[] { Color.RED }, (Color[]) w.map.get("k"));

        try {
            mapper.readValue(aposToQuotes("{'map':['java.util.HashMap<java.lang.String,[L"
                    + GADGET + ";>',{'k':[{}]}]}"),
                    ArrayMapWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    /*
    /**********************************************************************
    /* Array type ids: element type must be validated too
    /**********************************************************************
     */

    private ObjectMapper serializableMapper(Class<?>... allowedSubTypes) {
        BasicPolymorphicTypeValidator.Builder b = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(java.io.Serializable.class);
        for (Class<?> cls : allowedSubTypes) {
            b = b.allowIfSubType(cls);
        }
        return jsonMapperBuilder()
                .polymorphicTypeValidator(b.build())
                .build();
    }

    public void testArrayTypeIdGadgetElementRejected() throws Exception
    {
        // Every array type is `Serializable` (even if element type is not)
        ObjectMapper mapper = serializableMapper();
        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + GADGET + ";',[{'cmd':'x'}]]}"),
                    SerializableWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }

        try {
            mapper.readValue(aposToQuotes("{'value':['[[L" + GADGET + ";',[[{'cmd':'x'}]]]}"),
                    SerializableWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + SafeBean.class.getName()
                    + ";',[{'data':'x'}]]}"), SerializableWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, SafeBean.class.getName());
        }
    }

    public void testArrayTypeIdSafeElementAccepted() throws Exception
    {
        SerializableWrapper w = serializableMapper().readValue(
                aposToQuotes("{'value':['[Ljava.lang.String;',['a']]}"), SerializableWrapper.class);
        assertArrayEquals(new String[] { "a" }, (String[]) w.value);

        w = serializableMapper().readValue(aposToQuotes("{'value':['[I',[1]]}"), SerializableWrapper.class);
        assertArrayEquals(new int[] { 1 }, (int[]) w.value);

        w = serializableMapper(SafeBean.class).readValue(aposToQuotes("{'value':['[L"
                + SafeBean.class.getName() + ";',[{'data':'x'}]]}"), SerializableWrapper.class);
        assertEquals("x", ((SafeBean[]) w.value)[0].data);
    }

    // Array type id for exactly the declared type: element type not selected by attacker
    public void testDefaultTypingDeclaredArrayTypeAccepted() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        // approves array base type (but not `SafeBean` for base `Object`)
                        .allowIfBaseType(SafeBean[].class)
                        .allowIfBaseType(SafeBean.class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        BeanArrayWrapper input = new BeanArrayWrapper();
        SafeBean bean = new SafeBean();
        bean.data = "x";
        input.beans = new SafeBean[] { bean };
        String json = mapper.writeValueAsString(input);
        assertTrue(json, json.contains("[L" + SafeBean.class.getName() + ";"));
        BeanArrayWrapper result = mapper.readValue(json, BeanArrayWrapper.class);
        assertEquals("x", result.beans[0].data);
    }

    // Approval of declared array type covers arrays of subtypes of its element type
    public void testDefaultTypingApprovedArrayBaseCoversElementSubtypes() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(SafeBean[].class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        BeanArrayWrapper result = mapper.readValue(aposToQuotes("{'beans':['[L"
                + FinalSubBean.class.getName() + ";',[{'extra':4}]]}"), BeanArrayWrapper.class);
        assertEquals(FinalSubBean[].class, result.beans.getClass());
        assertEquals(4, ((FinalSubBean) result.beans[0]).extra);
    }

    // Element type of array type id that is subtype of declared element type
    public void testDefaultTypingDeclaredArraySubtypeAccepted() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(SafeBean[].class)
                        .allowIfBaseType(SafeBean.class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        BeanArrayWrapper input = new BeanArrayWrapper();
        SubBean bean = new SubBean();
        bean.data = "x";
        bean.extra = 3;
        input.beans = new SubBean[] { bean };
        String json = mapper.writeValueAsString(input);
        assertTrue(json, json.contains("[L" + SubBean.class.getName() + ";"));
        BeanArrayWrapper result = mapper.readValue(json, BeanArrayWrapper.class);
        assertEquals(SubBean[].class, result.beans.getClass());
        assertEquals(3, ((SubBean) result.beans[0]).extra);
    }

    // ... but approval of declared array type does not cover any element type
    public void testDefaultTypingDeclaredObjectArrayGadgetRejected() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Object[].class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        try {
            mapper.readValue(aposToQuotes("{'values':['[L" + GADGET + ";',[]]}"),
                    ObjectArrayWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
    }

    public void testDefaultTypingEnumContainersRoundTrip() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Map.class)
                        .allowIfBaseType(Collection.class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        EnumContainersWrapper input = new EnumContainersWrapper();
        input.enumMap = new EnumMap<>(Color.class);
        input.enumMap.put(Color.RED, "r");
        input.enumSet = EnumSet.of(Color.GREEN);
        String json = mapper.writeValueAsString(input);
        // Jackson itself writes generic type ids for these:
        assertTrue(json, json.contains("java.util.EnumMap<"));
        assertTrue(json, json.contains("java.util.EnumSet<"));
        EnumContainersWrapper result = mapper.readValue(json, EnumContainersWrapper.class);
        assertEquals(input.enumMap, result.enumMap);
        assertEquals(input.enumSet, result.enumSet);
    }

    /*
    /**********************************************************************
    /* Deny list applies to type parameters even if validator allows all
    /**********************************************************************
     */

    public void testDenyListedTypeParameterRejected() throws Exception
    {
        // Default (laissez-faire) validator for annotation-based typing, base type
        // `Object`: contained types are allowed by validator, but not by deny list
        ObjectMapper mapper = newJsonMapper();
        try {
            mapper.readValue(aposToQuotes("{'value':{'@class':'" + ENV
                    + "<java.util.logging.FileHandler>','payload':{}}}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidDefinitionException e) {
            verifyException(e, "Illegal type");
            verifyException(e, "prevented for security reasons");
            verifyException(e, "java.util.logging.FileHandler");
        }
    }

    /*
    /**********************************************************************
    /* Default (laissez-faire) validator
    /**********************************************************************
     */

    // Laissez-faire validator allows all subtypes of base type, but contained types
    // need to be subtypes of base type as well (not just of `Object`)
    public void testLaissezFaireNonSubtypeTypeParameterRejected() throws Exception
    {
        ObjectMapper mapper = newJsonMapper();
        try {
            mapper.readValue(msgJson(ENV + "<" + GADGET + ">",
                    "\"payload\":{\"cmd\":\"x\"}"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "not a subtype of base type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        // also as element type of (nested) arrays
        try {
            mapper.readValue(msgJson(ENV + "<[[L" + GADGET + ";>",
                    "\"payload\":[[{\"cmd\":\"x\"}]]"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "not a subtype of base type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        MsgWrapper w = mapper.readValue(msgJson(ENV + "<java.lang.String>", "\"payload\":\"b\""),
                MsgWrapper.class);
        assertEquals("b", ((Env<?>) w.msg).payload);
        w = mapper.readValue(msgJson(ENV + "<" + PlainMsg.class.getName() + ">",
                "\"payload\":{\"@class\":\"" + PlainMsg.class.getName() + "\",\"text\":\"x\"}"),
                MsgWrapper.class);
        assertEquals("x", ((PlainMsg) ((Env<?>) w.msg).payload).text);
    }

    public void testLaissezFaireDefaultTyping() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(LaissezFaireSubTypeValidator.instance, DefaultTyping.NON_FINAL)
                .build();
        // Map key not subtype of `Map`: rejected
        try {
            mapper.readValue(aposToQuotes("{'map':['java.util.HashMap<" + GADGET
                    + ",java.lang.String>',{'attacker-chosen':'x'}]}"),
                    StringMapWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "not a subtype of base type");
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        // Array of subtype of declared element type: fine
        BeanArrayWrapper input = new BeanArrayWrapper();
        SubBean bean = new SubBean();
        bean.extra = 5;
        input.beans = new SubBean[] { bean };
        BeanArrayWrapper result = mapper.readValue(mapper.writeValueAsString(input),
                BeanArrayWrapper.class);
        assertEquals(5, ((SubBean) result.beans[0]).extra);
    }

    /*
    /**********************************************************************
    /* Array type ids approved by sub-type matcher
    /**********************************************************************
     */

    public void testArrayTypeIdApprovedBySubTypeMatcher() throws Exception
    {
        // Every array type is `Serializable`, even if element type is not
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(java.io.Serializable.class)
                        .build())
                .build();
        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + GADGET + ";',[{'cmd':'x'}]]}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        ObjectValueWrapper w = mapper.readValue(aposToQuotes("{'value':['[Ljava.lang.String;',['a']]}"),
                ObjectValueWrapper.class);
        assertArrayEquals(new String[] { "a" }, (String[]) w.value);
    }

    // Abstract element types are not exempt: may still be deserializable
    public void testAbstractArrayElementTypeValidated() throws Exception
    {
        // Name-only allow-list for the generic type
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(ENV)
                        .build())
                .build();
        try {
            mapper.readValue(msgJson(ENV + "<[L" + ABSTRACT_GADGET + ";>",
                    "\"payload\":[{\"cmd\":\"x\"}]"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, ABSTRACT_GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        // Array type id approved by sub-type matcher (every array is `Serializable`)
        ObjectMapper mapper2 = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(java.io.Serializable.class)
                        .build())
                .build();
        try {
            mapper2.readValue(aposToQuotes("{'value':['[L" + ABSTRACT_GADGET + ";',[{'cmd':'x'}]]}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, ABSTRACT_GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    // ... even with `allowIfSubTypeIsArray()`
    public void testAbstractArrayElementTypeWithArraySupport() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(ENV)
                        .allowIfSubTypeIsArray()
                        .build())
                .build();
        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + ABSTRACT_GADGET + ";',[{'cmd':'x'}]]}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, ABSTRACT_GADGET);
        }
        try {
            mapper.readValue(msgJson(ENV + "<[L" + ABSTRACT_GADGET + ";>",
                    "\"payload\":[{\"cmd\":\"x\"}]"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, ABSTRACT_GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        // but fine if allow-listed
        ObjectMapper mapper2 = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(Msg.class)
                        .allowIfSubTypeIsArray()
                        .build())
                .build();
        MsgWrapper w = mapper2.readValue(msgJson(ENV + "<[L" + Msg.class.getName() + ";>",
                "\"payload\":[{\"@class\":\"" + ENV + "\"}]"), MsgWrapper.class);
        Object[] payload = (Object[]) ((Env<?>) w.msg).payload;
        assertEquals(Msg[].class, payload.getClass());
        assertEquals(Env.class, payload[0].getClass());
    }

    // `Object[]` (with legacy default typing) accepts any element type
    public void testLaissezFaireDeclaredObjectArrayRoundTrip() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(LaissezFaireSubTypeValidator.instance, DefaultTyping.NON_FINAL)
                .build();
        ObjectArrayWrapper input = new ObjectArrayWrapper();
        SubBean bean = new SubBean();
        bean.extra = 7;
        input.values = new SubBean[] { bean };
        ObjectArrayWrapper result = mapper.readValue(mapper.writeValueAsString(input),
                ObjectArrayWrapper.class);
        assertEquals(SubBean[].class, result.values.getClass());
        assertEquals(7, ((SubBean) result.values[0]).extra);

        input.values = new Date[] { new Date(123L) };
        result = mapper.readValue(mapper.writeValueAsString(input), ObjectArrayWrapper.class);
        assertArrayEquals(new Date[] { new Date(123L) }, result.values);

        // nested arrays too
        input.values = new Date[][] { { new Date(456L) } };
        result = mapper.readValue(mapper.writeValueAsString(input), ObjectArrayWrapper.class);
        assertEquals(Date[][].class, result.values.getClass());
        assertArrayEquals(new Date[] { new Date(456L) }, (Date[]) result.values[0]);
    }

    // `Serializable` (like `Object`) accepts arrays of any element type
    public void testLaissezFaireSerializableArrayRoundTrip() throws Exception
    {
        ObjectMapper mapper = newJsonMapper();
        SerializableWrapper input = new SerializableWrapper();
        SafeBean bean = new SafeBean();
        bean.data = "x";
        // `SafeBean` itself is not `Serializable`, but its arrays are
        input.value = new SafeBean[] { bean };
        SerializableWrapper result = mapper.readValue(mapper.writeValueAsString(input),
                SerializableWrapper.class);
        assertEquals(SafeBean[].class, result.value.getClass());
        assertEquals("x", ((SafeBean[]) result.value)[0].data);

        input.value = new SafeBean[][] { { bean } };
        result = mapper.readValue(mapper.writeValueAsString(input), SerializableWrapper.class);
        assertEquals(SafeBean[][].class, result.value.getClass());
        assertEquals("x", ((SafeBean[][]) result.value)[0][0].data);
    }

    /**
     * Stand-in gadget type that is `Serializable` (and `Cloneable`), like many real
     * ones; final so that `NON_FINAL` default typing gives its instances no type id
     * of their own, which would be validated separately
     */
    public static final class SerializableGadget extends Gadget implements java.io.Serializable, Cloneable {
        private static final long serialVersionUID = 1L;
    }

    // (final: no type id on the wrapper itself under `NON_FINAL` default typing)
    static final class SerializableMatrixWrapper {
        public java.io.Serializable[][] value;
    }

    static final class ObjectMatrixWrapper {
        public Object[][] value;
    }

    static final class ObjectFieldWrapper {
        public Object value;
    }

    /**
     * Approves any array (and {@code Env}) for any base type, and allows arrays
     * explicitly (so that their element types are not validated) for base
     * {@code Object[][]} only
     */
    static class ExplicitForOneBaseTypeValidator extends PolymorphicTypeValidator.Base {
        private static final long serialVersionUID = 1L;

        @Override
        public Validity validateSubType(MapperConfig<?> config, JavaType baseType,
                JavaType subType) {
            // (and `Env`, so that an array type parameter of it gets looked at)
            return (subType.isArrayType() || subType.hasRawClass(Env.class))
                    ? Validity.ALLOWED : Validity.INDETERMINATE;
        }

        @Override
        public boolean isArrayTypeAllowedExplicitly(MapperConfig<?> config, JavaType baseType,
                JavaType arrayType) {
            return baseType.hasRawClass(Object[][].class);
        }
    }

    private static String nestedArrayJson(String property, String elementType, int depth)
    {
        String dims = "", open = "", close = "";
        for (int i = 0; i < depth; ++i) {
            dims += "["; open += "["; close += "]";
        }
        return aposToQuotes("{'" + property + "':['" + dims + "L" + elementType + ";',"
                + open + "{'cmd':'x'}" + close + "]}");
    }

    private void _assertGadgetArrayRejected(ObjectMapper mapper, String json, Class<?> target,
            String rule) throws Exception
    {
        try {
            mapper.readValue(json, target);
            fail("Should not pass: " + rule);
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, SerializableGadget.class.getName());
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    // A rule every array of some depth matches (`Object[][]` for all 2-D
    // reference arrays, `Serializable[]` for all arrays of `Serializable`
    // elements, a name pattern for all non-JDK arrays) approves the array and
    // not its element type, whatever the depth of the type id
    public void testArrayRuleMatchingEveryArrayOfDepthRejected() throws Exception
    {
        final String gadget = SerializableGadget.class.getName();
        final Object[][] cases = {
            // rule, depth of the type id
            { Object[][].class, 2 }, { Object[][][].class, 3 },
            { java.io.Serializable[].class, 1 }, { java.io.Serializable[][].class, 2 },
            { Cloneable[].class, 1 }, { Cloneable[][].class, 2 },
            // rule for one depth, type id of a deeper one (`Gadget[][]` is an `Object[]`)
            { Object[].class, 2 }, { Object[][].class, 3 },
            // name pattern matching all 2-D arrays of non-JDK classes
            { java.util.regex.Pattern.compile("\\[\\[L(?!java\\.).*"), 2 },
        };
        for (Object[] c : cases) {
            BasicPolymorphicTypeValidator.Builder b = BasicPolymorphicTypeValidator.builder();
            if (c[0] instanceof Class<?>) {
                b = b.allowIfSubType((Class<?>) c[0]);
            } else {
                b = b.allowIfSubType((java.util.regex.Pattern) c[0]);
            }
            ObjectMapper mapper = jsonMapperBuilder()
                    .polymorphicTypeValidator(b.build())
                    .build();
            _assertGadgetArrayRejected(mapper, nestedArrayJson("value", gadget, (Integer) c[1]),
                    ObjectValueWrapper.class, String.valueOf(c[0]));
        }
        // but a rule for exactly the 2-D array class covers its elements
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(SafeBean[][].class)
                        .build())
                .build();
        ObjectValueWrapper w = mapper.readValue(aposToQuotes("{'value':['[[L" + SafeBean.class.getName()
                + ";',[[{'data':'x'}]]]}"), ObjectValueWrapper.class);
        assertEquals("x", ((SafeBean[][]) w.value)[0][0].data);
    }

    // A name rule for JDK arrays matches every array of a JDK element type, so
    // the element type is validated on its own (`Date` here: not exempt, not
    // allow-listed, and harmless if ever constructed)
    public void testArrayRuleMatchingJdkArraysRejected() throws Exception
    {
        for (Object rule : new Object[] { "[Ljava.", java.util.regex.Pattern.compile("\\[+Ljava\\..*") }) {
            BasicPolymorphicTypeValidator.Builder b = BasicPolymorphicTypeValidator.builder();
            b = (rule instanceof String) ? b.allowIfSubType((String) rule)
                    : b.allowIfSubType((java.util.regex.Pattern) rule);
            ObjectMapper mapper = jsonMapperBuilder()
                    .polymorphicTypeValidator(b.build())
                    .build();
            try {
                mapper.readValue(aposToQuotes("{'value':['[Ljava.util.Date;',[0]]}"),
                        ObjectValueWrapper.class);
                fail("Should not pass: " + rule);
            } catch (InvalidTypeIdException e) {
                verifyException(e, "denied resolution of contained type");
                verifyException(e, "java.util.Date");
            }
        }
    }

    // Approval of a declared `Serializable[][]` (or `Object[][]`, `Cloneable[][]`)
    // base type covers subtypes of its element type no more than a subtype rule
    // for it does: every gadget is one
    public void testApprovedUniversalArrayBaseTypeDoesNotCoverElements() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(java.io.Serializable[][].class)
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        _assertGadgetArrayRejected(mapper,
                nestedArrayJson("value", SerializableGadget.class.getName(), 2),
                SerializableMatrixWrapper.class, "allowIfBaseType(Serializable[][])");
    }

    // The validator is asked about an array type it approved as subtype, with the
    // base type that was approved for; inner dimensions and array type parameters
    // are never asked about, since no validator approved them
    public void testExplicitSignalOnlyForApprovedArrayAndItsBaseType() throws Exception
    {
        final String gadget = SerializableGadget.class.getName();
        ObjectMapper mapper = jsonMapperBuilder()
                .activateDefaultTyping(new ExplicitForOneBaseTypeValidator(), DefaultTyping.NON_FINAL)
                .build();
        // base type `Object[][]`: allowed explicitly, elements not validated
        ObjectMatrixWrapper w = mapper.readValue(nestedArrayJson("value", gadget, 2),
                ObjectMatrixWrapper.class);
        assertEquals(SerializableGadget.class, w.value[0][0].getClass());
        INSTANTIATIONS.clear();

        // base type `Object`: same array type, not allowed explicitly
        _assertGadgetArrayRejected(mapper, nestedArrayJson("value", gadget, 2),
                ObjectFieldWrapper.class, "base Object");
        // as type parameter: not asked about at all
        try {
            mapper.readValue(aposToQuotes("{'value':['" + ENV + "<[[L" + gadget + ";>',"
                    + "{'payload':[[{'cmd':'x'}]]}]}"), ObjectFieldWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, gadget);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    // Approval of an array type covers its element type only when given for
    // exactly that class: `allowIfSubType(Bar[].class)` names the application's
    // choice of elements, a name pattern matching `[Lcom.foo.Bar;` cannot be told
    // from one matching every array of a package or depth. And only for an array
    // named directly by a type id: as a type parameter, the array itself is not
    // approved by any rule, so its element type needs one
    public void testExplicitArrayRuleCoversElementType() throws Exception
    {
        final String json = aposToQuotes("{'value':['[L" + SafeBean.class.getName() + ";',[{'data':'x'}]]}");
        final String asParameter = aposToQuotes("{'value':['" + ENV + "<[L" + SafeBean.class.getName()
                + ";>',{'payload':[{'data':'y'}]}]}");
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(Env.class)
                        .allowIfSubType(SafeBean[].class)
                        .build())
                .build();
        ObjectValueWrapper w = mapper.readValue(json, ObjectValueWrapper.class);
        assertEquals("x", ((SafeBean[]) w.value)[0].data);
        try {
            mapper.readValue(asParameter, ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, SafeBean.class.getName());
        }
        ObjectMapper allowing = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(Env.class)
                        .allowIfSubType(SafeBean[].class)
                        .allowIfSubType(SafeBean.class)
                        .build())
                .build();
        w = allowing.readValue(asParameter, ObjectValueWrapper.class);
        assertEquals("y", ((SafeBean[]) ((Env<?>) w.value).payload)[0].data);
        // but not other array types
        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + GADGET + ";',[{'cmd':'x'}]]}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);

        // nor deeper arrays of the same element type: `SafeBean[][]` approved by a
        // rule every 2-D array matches, `SafeBean` itself still validated
        ObjectMapper deeper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(SafeBean[].class)
                        .allowIfSubType(Object[].class)
                        .build())
                .build();
        try {
            deeper.readValue(aposToQuotes("{'value':['[[L" + SafeBean.class.getName()
                    + ";',[[{'data':'x'}]]]}"), ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, SafeBean.class.getName());
        }

        // arrays of subtypes of the listed element type are covered, as by any class rule
        ObjectValueWrapper sub = mapper.readValue(aposToQuotes("{'value':['[L" + FinalSubBean.class.getName()
                + ";',[{'data':'x','extra':4}]]}"), ObjectValueWrapper.class);
        assertEquals(4, ((FinalSubBean[]) sub.value)[0].extra);
    }

    // The array class named by the rule counts whatever its element type: elements
    // of an exactly named `Serializable[]` are of an abstract type and get type ids
    // of their own
    public void testExactUniversalArrayRuleCoversItself() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(java.io.Serializable[].class)
                        .build())
                .build();
        ObjectValueWrapper w = mapper.readValue(aposToQuotes("{'value':['[Ljava.io.Serializable;',[]]}"),
                ObjectValueWrapper.class);
        assertEquals(java.io.Serializable[].class, w.value.getClass());
        // but not an array of a `Serializable` gadget
        _assertGadgetArrayRejected(mapper, nestedArrayJson("value", SerializableGadget.class.getName(), 1),
                ObjectValueWrapper.class, "allowIfSubType(Serializable[])");
    }

    public void testNameBasedArrayRuleDoesNotCoverElementType() throws Exception
    {
        final String json = aposToQuotes("{'value':['[L" + SafeBean.class.getName() + ";',[{'data':'x'}]]}");
        final java.util.regex.Pattern exactName = java.util.regex.Pattern.compile(
                java.util.regex.Pattern.quote("[L" + SafeBean.class.getName() + ";"));
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(exactName)
                        .build())
                .build();
        try {
            mapper.readValue(json, ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, SafeBean.class.getName());
        }

        // with a rule for the element type as well: fine
        ObjectMapper allowing = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(exactName)
                        .allowIfSubType(SafeBean.class)
                        .build())
                .build();
        assertEquals("x", ((SafeBean[]) allowing.readValue(json, ObjectValueWrapper.class).value)[0].data);
    }

    // ... but not approval that covers all array types (like `Object[]`)
    public void testNonSpecificallyApprovedArrayTypeElementValidated() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType("[L")
                        .build())
                .build();
        try {
            mapper.readValue(aposToQuotes("{'value':['[L" + GADGET + ";',[{'cmd':'x'}]]}"),
                    ObjectValueWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    /*
    /**********************************************************************
    /* JDK containers as type parameters
    /**********************************************************************
     */

    public void testJdkContainerTypeParametersAccepted() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Msg.class)
                        .build())
                .build();
        MsgWrapper w = mapper.readValue(msgJson(ENV + "<java.util.List<java.lang.String>>",
                "\"payload\":[\"a\"]"), MsgWrapper.class);
        assertEquals(Arrays.asList("a"), ((Env<?>) w.msg).payload);
        w = mapper.readValue(msgJson(ENV + "<java.util.ArrayList<java.lang.String>>",
                "\"payload\":[\"b\"]"), MsgWrapper.class);
        assertEquals(Arrays.asList("b"), ((Env<?>) w.msg).payload);
        w = mapper.readValue(msgJson(ENV + "<java.util.HashMap<java.lang.String,java.lang.Integer>>",
                "\"payload\":{\"c\":1}"), MsgWrapper.class);
        assertEquals(Collections.singletonMap("c", 1), ((Env<?>) w.msg).payload);
        w = mapper.readValue(msgJson(ENV
                + "<java.util.concurrent.atomic.AtomicReference<java.lang.String>>",
                "\"payload\":\"d\""), MsgWrapper.class);
        assertEquals("d", ((java.util.concurrent.atomic.AtomicReference<?>) ((Env<?>) w.msg).payload).get());

        // ... but their contents are still validated
        try {
            mapper.readValue(msgJson(ENV + "<java.util.ArrayList<" + GADGET + ">>",
                    "\"payload\":[{}]"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, GADGET);
        }
        assertEquals(Collections.emptyList(), INSTANTIATIONS);
    }

    /*
    /**********************************************************************
    /* Validators that deny `Object` as base type
    /**********************************************************************
     */

    // Intentional: contained types that are not subtypes of base type are validated
    // as type ids for base type `Object`, which such validators deny
    public void testObjectBaseDenyingValidatorRejectsAllowListedTypeParameter() throws Exception
    {
        ObjectMapper mapper = jsonMapperBuilder()
                .polymorphicTypeValidator(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(Msg.class)
                        .allowIfSubType(SafeBean.class)
                        .denyForExactBaseType(Object.class)
                        .build())
                .build();
        try {
            mapper.readValue(msgJson(ENV + "<" + SafeBean.class.getName() + ">",
                    "\"payload\":{\"data\":\"x\"}"), MsgWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "denied resolution of contained type");
            verifyException(e, SafeBean.class.getName());
        }
    }

    private String msgJson(String typeId, String props) {
        return "{\"msg\":{\"@class\":\"" + typeId + "\"," + props + "}}";
    }
}
