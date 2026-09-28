package com.cloudsec.state;

import java.time.Instant;

/** Where and when a principal was last seen, used by the impossible-travel rule. */
public record Sighting(String region, double latitude, double longitude, String sourceIp, Instant at) {
}
