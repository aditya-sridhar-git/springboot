package com.cloudsec.engine;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class GeoRegionsTest {

    @Test
    @DisplayName("great-circle distance matches published figures within a percent")
    void distanceIsAccurate() {
        // N. Virginia to Singapore is about 15,500 km.
        double km = GeoRegions.distanceKm(38.95, -77.45, 1.35, 103.82);
        assertThat(km).isBetween(15_300.0, 15_800.0);

        // London to Frankfurt is about 640 km.
        assertThat(GeoRegions.distanceKm(51.51, -0.13, 50.11, 8.68)).isBetween(600.0, 680.0);
    }

    @Test
    void distanceBetweenIdenticalPointsIsZero() {
        assertThat(GeoRegions.distanceKm(19.08, 72.88, 19.08, 72.88)).isZero();
    }

    @Test
    void knownRegionsResolveAndUnknownOnesDoNot() {
        assertThat(GeoRegions.of("ap-southeast-1")).isPresent()
                .get().extracting(GeoRegions.Coordinates::label).isEqualTo("Singapore");
        assertThat(GeoRegions.of("mars-north-1")).isEmpty();
        assertThat(GeoRegions.of(null)).isEmpty();
    }
}
