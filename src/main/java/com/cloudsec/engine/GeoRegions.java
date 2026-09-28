package com.cloudsec.engine;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Approximate coordinates for cloud regions.
 *
 * <p>Real deployments resolve the source IP through a GeoIP database. Region centroids are a good
 * enough stand-in here and they behave identically for the impossible-travel maths.
 */
public final class GeoRegions {

    public record Coordinates(double latitude, double longitude, String label) {
    }

    private static final Map<String, Coordinates> REGIONS = new LinkedHashMap<>();

    static {
        REGIONS.put("us-east-1", new Coordinates(38.95, -77.45, "N. Virginia"));
        REGIONS.put("us-east-2", new Coordinates(40.00, -83.00, "Ohio"));
        REGIONS.put("us-west-1", new Coordinates(37.35, -121.96, "N. California"));
        REGIONS.put("us-west-2", new Coordinates(45.87, -119.69, "Oregon"));
        REGIONS.put("ca-central-1", new Coordinates(45.50, -73.57, "Montreal"));
        REGIONS.put("sa-east-1", new Coordinates(-23.55, -46.63, "Sao Paulo"));
        REGIONS.put("eu-west-1", new Coordinates(53.35, -6.26, "Ireland"));
        REGIONS.put("eu-west-2", new Coordinates(51.51, -0.13, "London"));
        REGIONS.put("eu-central-1", new Coordinates(50.11, 8.68, "Frankfurt"));
        REGIONS.put("eu-north-1", new Coordinates(59.33, 18.06, "Stockholm"));
        REGIONS.put("af-south-1", new Coordinates(-33.92, 18.42, "Cape Town"));
        REGIONS.put("me-south-1", new Coordinates(26.07, 50.55, "Bahrain"));
        REGIONS.put("ap-south-1", new Coordinates(19.08, 72.88, "Mumbai"));
        REGIONS.put("ap-southeast-1", new Coordinates(1.35, 103.82, "Singapore"));
        REGIONS.put("ap-southeast-2", new Coordinates(-33.87, 151.21, "Sydney"));
        REGIONS.put("ap-northeast-1", new Coordinates(35.68, 139.69, "Tokyo"));
        REGIONS.put("ap-northeast-2", new Coordinates(37.57, 126.98, "Seoul"));
        REGIONS.put("ap-east-1", new Coordinates(22.32, 114.17, "Hong Kong"));
        REGIONS.put("cn-north-1", new Coordinates(39.90, 116.41, "Beijing"));
        REGIONS.put("ru-central-1", new Coordinates(55.75, 37.62, "Moscow"));
    }

    private static final double EARTH_RADIUS_KM = 6371.0088;

    private GeoRegions() {
    }

    public static Optional<Coordinates> of(String region) {
        return region == null ? Optional.empty() : Optional.ofNullable(REGIONS.get(region));
    }

    public static Map<String, Coordinates> all() {
        return Map.copyOf(REGIONS);
    }

    /** Great-circle distance in kilometres. */
    public static double distanceKm(double lat1, double lon1, double lat2, double lon2) {
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1.0, Math.sqrt(a)));
    }
}
