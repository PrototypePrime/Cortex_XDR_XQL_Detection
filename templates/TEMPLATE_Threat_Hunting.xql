/*
==============================================================================
CORTEX XDR THREAT HUNTING TEMPLATE
Framework: Hypothesis-Driven Hunting (PEAK)
==============================================================================
Hunt Name: [Name]
Hypothesis: [e.g., "Adversaries are using rare LOLBins to evade detection."]

Goal: [What are we trying to find?]
Scope: [Timeframe, specific subnets, specific host groups]

Assumptions:
1. Logs are available for the target timeframe.
2. Baseline of "normal" is understood.
==============================================================================
*/

// --- HUNT QUERY ---

// Step 1: Broad Search
config case_sensitive = false timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.PROCESS_LAUNCH

// Step 2: Filter Known Good (The "Noise")
| filter actor_process_image_name not in ("svchost.exe", "explorer.exe")

// Step 3: Look for Outliers / Rare Events
| comp count() as execution_count by actor_process_image_name
| filter execution_count < 5  // Rare execution frequency

// Step 4: Investigate
| sort asc execution_count
| fields actor_process_image_name, execution_count
