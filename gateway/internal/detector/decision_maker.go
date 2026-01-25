package detector

type Verdict string

const (
	Block   Verdict = "BLOCK"
	Monitor Verdict = "MONITOR"
	Allow   Verdict = "ALLOW"
)

// Decide centralizes the blocking logic
// Returns: (Verdict, Reason, Source)
// Source indicates who made the decision: "Rule Engine", "ML Engine", or "Hybrid"
func Decide(ruleScore int, ruleBlock bool, mlAnomaly bool, mlConfidence float64) (Verdict, string, string) {
	// ------------------------------------------
	// 1.Critical Rules (The "Must Block" Layer)
	// ------------------------------------------
	if ruleBlock {
		return Block, "Critical Rule Match", "Rule Engine"
	}

	// If the rule score is huge, we don't even need ML.
	if ruleScore >= 15 {
		return Block, "High Risk Rule Score", "Rule Engine"
	}

	if mlConfidence > 0.8 {
		return Block, "AI/Hybrid Anomaly Detected", "ML Engine"
	}

	if mlConfidence > 0.65 {
		return Monitor, "Suspicious Activity (Medium Risk)", "ML Engine"
	}

	if ruleScore >= 10 && mlConfidence > 0.40 {
		return Monitor, "Combined Rule+ML Suspicion", "Hybrid"
	}

	return Allow, "Clean", "None"
}