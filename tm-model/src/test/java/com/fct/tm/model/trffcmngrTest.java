//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.tm.model;

import static org.junit.Assert.*;

import org.junit.Test;

import java.util.UUID;

import com.hp.api.Id;

/**
 * Sample test of the trffcmngr domain model.
 */
public class trffcmngrTest {

    @Test
    public void basic() {
        Id<trffcmngr, UUID> id = Id.valueOf(UUID.randomUUID());
        trffcmngr s = new trffcmngr(id, "Gizmo");
        assertEquals("incorrect id", id, s.getId());
        assertEquals("incorrect name", "Gizmo", s.name());
    }

}
