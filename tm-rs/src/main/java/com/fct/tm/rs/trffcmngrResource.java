//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.tm.rs;

import com.hp.sdn.rs.misc.ControllerResource;

import java.util.UUID;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.fct.tm.model.trffcmngr;
import com.fct.tm.api.trffcmngrService;

import com.hp.api.Id;

/**
 * Sample trffcmngr REST API resource.
 */
@Path("trffcmngr")
public class trffcmngrResource extends ControllerResource {

    /**
     * Gets JSON array of all trffcmngr items.
     * <p>
     * Normal Response Code(s): ok (200)
     * <p>
     * Error Response Codes: unauthorized (401), forbidden (403), badMethod
     * (405), serviceUnavailable (503)
     * 
     * @return JSON array
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAll() {
        trffcmngrService svc = get(trffcmngrService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        List<JsonNode> nodes = new ArrayList<JsonNode>();
        //for (trffcmngr s : svc.getAll())
        //    nodes.add(json(s, mapper));

        ArrayNode rowNode = root.putArray("trffcmngr");
        rowNode.addAll(nodes);

        return ok(root.toString()).build();
    }

    /**
     * Creates a new trffcmngr and registers it.
     * <p>
     * Normal Response Code(s): ok (200)
     * <p>
     * Error Response Codes: badRequest (400), unauthorized (401), forbidden (403), 
     * badMethod (405), serviceUnavailable (503)
     * 
     * @param request JSON representation of a trffcmngr to be created
     * @return JSON object
     */
//    @POST
//    @Produces(MediaType.APPLICATION_JSON)
//    public Response create(String request) {
//        trffcmngrService svc = get(trffcmngrService.class);
//
//        // Decode request
//        ObjectMapper mapper = new ObjectMapper();
//        JsonNode root = parse(mapper, request, "trffcmngr data");
//        JsonNode node = root.path("item");
//        
//        String name = exists(node, "name") ? node.path("name").asText() : null;
//
//        // Call the service
//        //trffcmngr s = svc.create(name);
//
//        // Encode response
//        return response(s, mapper).build();
//    }

    /**
     * Gets the specified trffcmngr by its identifier.
     * <p>
     * Normal Response Code(s): ok (200)
     * <p>
     * Error Response Codes: badRequest (400), unauthorized (401), forbidden (403), 
     * badMethod (405), serviceUnavailable (503), itemNotFound (404)
     * 
     * @param uid the trffcmngr unique identifier
     * @return JSON object
     */
//    @GET
//    @Path("{uid}")
//    @Produces(MediaType.APPLICATION_JSON)
//    public Response get(@PathParam("uid") String uid) {
//        trffcmngrService svc = get(trffcmngrService.class);
//        Id<trffcmngr, UUID> id = Id.valueOf(UUID.fromString(uid));
////        trffcmngr s = svc.get(id);
//
//        // Encode response
//        return response(s, new ObjectMapper()).build();
//    }

    /**
     * Deletes the specified trffcmngr.
     * <p>
     * Normal Response Code(s): ok (200)
     * <p>
     * Error Response Codes: badRequest (400), unauthorized (401), forbidden (403), 
     * badMethod (405), serviceUnavailable (503), itemNotFound (404)
     * 
     * @param uid the trffcmngr unique identifier
     * @return no data
     */
    @DELETE
    @Path("{uid}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response delete(@PathParam("uid") String uid) {
        trffcmngrService svc = get(trffcmngrService.class);
        Id<trffcmngr, UUID> id = Id.valueOf(UUID.fromString(uid));
//        svc.delete(id);
        // Encode response
        return Response.ok().build();
    }

    // Encode the response builder for the specified trffcmngr
    private ResponseBuilder response(trffcmngr s, ObjectMapper mapper) {
        ObjectNode r = mapper.createObjectNode();
        r.put("item", json(s, mapper));
        return ok(r.toString());
    }

    /**
     * Returns JSON string describing the given trffcmngr information.
     * 
     * @param s the trffcmngr
     * @param mapper JSON object mapper
     * @return the JSON node representing the specified trffcmngr information
     */
    static JsonNode json(trffcmngr s, ObjectMapper mapper) {
        ObjectNode node = mapper.createObjectNode();
        node.put("uid", s.getId().getValue().toString());
        node.put("name", s.name());
        return node;
    }

}
