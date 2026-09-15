# KQL implementation gaps (punch-list)

Exact names still missing from each OpenTide surface after the 2026-09-15 catalog expansion.

Related: [`coverage-gap.md`](coverage-gap.md), [`evaluate-plugins.md`](evaluate-plugins.md), [`control-commands.md`](control-commands.md), [`scalar-functions-geo-series.md`](scalar-functions-geo-series.md).

Legend: **MUST** = blocks 100% completion/hover/highlight fidelity; **SHOULD** = detection-quality; **NICE** = long-tail.

---

## a) Catalogs (`catalogs/kql`)

### `core/operators.toml` — 53 tabular

**Missing primary operators vs inventory:** none.

**SHOULD — richer `warning` metadata** (names already present):

- `search` — flag `search *` illegal in Sentinel analytics
- `union` — flag `union *` illegal in Sentinel analytics
- `join`, `union`, `externaldata` — Defender NRT ban
- `fork`, `facet` — multi-result / not for detections
- `find` — unbounded multi-table caveat

### `core/operators-scalar.toml` — 54

**Missing vs inventory/Learn:** none (includes `between`, `!between`, `-`, `*`).

### `core/functions.toml` — 298 (253 scalar + 45 aggregate)

**MUST — 111 Learn scalars absent** (full lists in [`scalar-functions-geo-series.md`](scalar-functions-geo-series.md)):

**`convert_*` (8):**  
`convert_angle`, `convert_energy`, `convert_force`, `convert_length`, `convert_mass`, `convert_speed`, `convert_temperature`, `convert_volume`

**`series_*` (51):**  
`series_abs`, `series_acos`, `series_add`, `series_asin`, `series_atan`, `series_ceiling`, `series_cos`, `series_cosine_similarity`, `series_decompose`, `series_decompose_anomalies`, `series_decompose_forecast`, `series_divide`, `series_dot_product`, `series_equals`, `series_exp`, `series_fft`, `series_fill_backward`, `series_fill_const`, `series_fill_forward`, `series_fill_linear`, `series_fir`, `series_fit_2lines`, `series_fit_2lines_dynamic`, `series_fit_line`, `series_fit_line_dynamic`, `series_fit_poly`, `series_floor`, `series_greater`, `series_greater_equals`, `series_ifft`, `series_iir`, `series_less`, `series_less_equals`, `series_log`, `series_magnitude`, `series_multiply`, `series_not_equals`, `series_outliers`, `series_pearson_correlation`, `series_periods_detect`, `series_periods_validate`, `series_pow`, `series_product`, `series_seasonal`, `series_sign`, `series_sin`, `series_stats`, `series_stats_dynamic`, `series_subtract`, `series_sum`, `series_tan`

**`geo_*` (52):**  
`geo_angle`, `geo_azimuth`, `geo_closest_point_on_line`, `geo_closest_point_on_polygon`, `geo_distance_2points`, `geo_distance_point_to_line`, `geo_distance_point_to_polygon`, `geo_from_wkt`, `geo_geohash_neighbors`, `geo_geohash_to_central_point`, `geo_geohash_to_polygon`, `geo_h3cell_children`, `geo_h3cell_level`, `geo_h3cell_neighbors`, `geo_h3cell_parent`, `geo_h3cell_rings`, `geo_h3cell_to_central_point`, `geo_h3cell_to_polygon`, `geo_intersection_2lines`, `geo_intersection_2polygons`, `geo_intersection_line_with_polygon`, `geo_intersects_2lines`, `geo_intersects_2polygons`, `geo_intersects_line_with_polygon`, `geo_line_buffer`, `geo_line_centroid`, `geo_line_densify`, `geo_line_interpolate_point`, `geo_line_length`, `geo_line_locate_point`, `geo_line_simplify`, `geo_line_to_s2cells`, `geo_point_buffer`, `geo_point_in_circle`, `geo_point_in_polygon`, `geo_point_to_geohash`, `geo_point_to_h3cell`, `geo_point_to_s2cell`, `geo_polygon_area`, `geo_polygon_buffer`, `geo_polygon_centroid`, `geo_polygon_densify`, `geo_polygon_perimeter`, `geo_polygon_simplify`, `geo_polygon_to_h3cells`, `geo_polygon_to_s2cells`, `geo_s2cell_neighbors`, `geo_s2cell_to_central_point`, `geo_s2cell_to_polygon`, `geo_simplify_polygons_array`, `geo_union_lines_array`, `geo_union_polygons_array`

**SHOULD — kind fix:** `hll_merge` is cataloged as `scalar`; Learn lists it under aggregations.

### Evaluate plugins — **no catalog file**

**MUST — catalog these 22 names** (from [`evaluate-plugins.md`](evaluate-plugins.md)):

`bag_unpack`, `pivot`, `autocluster`, `basket`, `diffpatterns`, `diffpatterns_text`, `sequence_detect`, `narrow`, `preview`, `rolling_percentile`, `rows_near`, `dcount_intersect`, `ipv4_lookup`, `ipv6_lookup`, `schema_merge`, `infer_storage_schema`, `sql_request`, `mysql_request`, `cosmosdb_sql_request`, `azure_digital_twins_query_request`, `python`, `R`