/*
==============================================================================
CORTEX XDR ANOMALY DETECTION TEMPLATE
Method: Behavioral Baseline Deviation
==============================================================================
Rule Name: [Metric] Anomaly
Description: Detects deviations from historical baseline (e.g., unusual data volume).

Baseline Period: 30 days
Analysis Period: 1 hour
==============================================================================
*/

// --- DETECTION QUERY ---
config case_sensitive = false timeframe = 30d
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
// Calculate baseline per host
| comp count() as total_connections by agent_hostname
| comp avg(total_connections) as avg_conn, stddev(total_connections) as stdev_conn

// Join with current activity (conceptual - XQL join logic varies)
// In practice, use XDR's "Analytics BIOC" or "IOC" features for stateful anomaly detection.
// This query demonstrates the statistical logic:
| alter threshold = avg_conn + (3 * stdev_conn)
| filter total_connections > threshold
| fields agent_hostname, total_connections, threshold
