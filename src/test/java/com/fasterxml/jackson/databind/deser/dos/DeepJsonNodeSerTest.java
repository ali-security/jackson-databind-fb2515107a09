package com.fasterxml.jackson.databind.deser.dos;

import com.fasterxml.jackson.databind.BaseMapTest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Tests for [databind#3447]: deeply nested {@link JsonNode}s must not cause
 * {@link StackOverflowError} for {@code toString()} / {@code toPrettyString()}.
 *<p>
 * NOTE: trees are built programmatically since reading of such deeply nested
 * documents (via {@code readTree()}) is itself recursive in this version.
 */
public class DeepJsonNodeSerTest extends BaseMapTest
{
    // Well beyond the depth at which recursive serialization overflows
    private final static int TOO_DEEP_NESTING = 100000;

    // Pretty-printed Object output grows quadratically with nesting (indentation)
    private final static int DEEP_PRETTY_OBJECT_NESTING = 2000;

    // Shallow enough for recursive (regular) serialization, to compare outputs with
    private final static int COMPARABLE_NESTING = 500;

    private final ObjectMapper MAPPER = newJsonMapper();

    public void testVeryDeepNodeSer() throws Exception
    {
        final int depth = TOO_DEEP_NESTING;
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode curr = root;
        for (int i = 0; i < depth; i++) {
            curr = curr.putObject("abc" + i);
        }

        StringBuilder exp = new StringBuilder();
        exp.append("{");
        for (int i = 0; i < depth; i++) {
            exp.append("\"abc").append(i).append("\":{");
        }
        for (int i = 0; i < depth; i++) {
            exp.append("}");
        }
        exp.append("}");

        String json = root.toString();
        assertNotNull(json);
        assertEquals(exp.toString(), json);
    }

    public void testVeryDeepArrayNodeSer() throws Exception
    {
        final int depth = TOO_DEEP_NESTING;
        // depth+1 arrays in total: root plus `depth` nested ones
        assertEquals(_arrays(depth + 1, "[", "]", ""), _deepArray(depth).toString());
    }

    // Arrays are pretty-printed inline (no indentation), so output stays linear
    public void testVeryDeepArrayNodePrettySer() throws Exception
    {
        final int depth = TOO_DEEP_NESTING;
        assertEquals(_arrays(depth + 1, "[ ", " ]", "[ ]"), _deepArray(depth).toPrettyString());
    }

    public void testVeryDeepMixedNodeSer() throws Exception
    {
        final int depth = TOO_DEEP_NESTING;
        final JsonNode root = _mixed(depth);
        String json = root.toString();
        assertNotNull(json);
        assertTrue(json.startsWith("{\"id\":0,\"list\":[\"x\",{\"id\":1,\"list\":[\"x\",{"));
        assertTrue(json.contains(",{\"id\":" + depth + "},\"end\"]},\"end\"]}"));
        assertTrue(json.endsWith("},\"end\"]},\"end\"]}"));
    }

    public void testVeryDeepObjectNodePrettySer() throws Exception
    {
        final int depth = DEEP_PRETTY_OBJECT_NESTING;
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode curr = root;
        for (int i = 0; i < depth; i++) {
            curr = curr.putObject("abc" + i);
        }
        String pretty = root.toPrettyString();
        assertNotNull(pretty);
        assertTrue(pretty.startsWith("{"));
        assertTrue(pretty.contains("\"abc" + (depth - 1) + "\" : { }"));
        assertTrue(pretty.endsWith("}"));
    }

    // Verify non-recursive serialization produces same output as regular
    // (recursive) serialization for nesting levels where latter works
    public void testNonRecursiveMatchesRegularSer() throws Exception
    {
        final JsonNode root = _mixed(COMPARABLE_NESTING);
        assertEquals(MAPPER.writeValueAsString(root), root.toString());
        assertEquals(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root),
                root.toPrettyString());

        ArrayNode arrays = _deepArray(COMPARABLE_NESTING);
        assertEquals(MAPPER.writeValueAsString(arrays), arrays.toString());
        assertEquals(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(arrays),
                arrays.toPrettyString());

        // and then a shallow but wide mix with empty containers, scalars
        ObjectNode misc = MAPPER.createObjectNode();
        misc.putArray("empty");
        misc.putObject("emptyOb");
        misc.put("str", "abc");
        misc.putNull("nil");
        ArrayNode arr = misc.putArray("arr");
        arr.add(1).add(true).addNull();
        arr.addObject().put("a", 1.25).putArray("b").addObject();
        arr.addArray().addArray();
        arr.add("last");
        misc.put("after", 3);
        assertEquals(MAPPER.writeValueAsString(misc), misc.toString());
        assertEquals(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(misc),
                misc.toPrettyString());

        // as well as scalar root values
        JsonNode scalar = MAPPER.getNodeFactory().textNode("root");
        assertEquals(MAPPER.writeValueAsString(scalar), scalar.toString());
    }

    // Builds {"id":0,"list":["x",{"id":1,"list":["x",{ ... }, "end"]}, "end"]}
    private JsonNode _mixed(int depth)
    {
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode curr = root;
        for (int i = 0; i < depth; i++) {
            curr.put("id", i);
            ArrayNode list = curr.putArray("list");
            list.add("x");
            ObjectNode next = list.addObject();
            list.add("end");
            curr = next;
        }
        curr.put("id", depth);
        return root;
    }

    private ArrayNode _deepArray(int depth)
    {
        ArrayNode root = MAPPER.createArrayNode();
        ArrayNode curr = root;
        for (int i = 0; i < depth; i++) {
            curr = curr.addArray();
        }
        return root;
    }

    private static String _arrays(int count, String open, String close, String innermost)
    {
        StringBuilder sb = new StringBuilder();
        if (innermost.isEmpty()) {
            for (int i = 0; i < count; i++) {
                sb.append(open);
            }
            for (int i = 0; i < count; i++) {
                sb.append(close);
            }
        } else {
            for (int i = 1; i < count; i++) {
                sb.append(open);
            }
            sb.append(innermost);
            for (int i = 1; i < count; i++) {
                sb.append(close);
            }
        }
        return sb.toString();
    }
}
