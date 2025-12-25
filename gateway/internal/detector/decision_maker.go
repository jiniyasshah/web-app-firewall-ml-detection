package detector

type Verdict string

const (
	Block   Verdict = "BLOCK"
	Monitor Verdict = "MONITOR"
	Allow   Verdict = "ALLOW"
)

// Decide centralizes the blocking logic
func Decide(ruleScore int, ruleBlock bool, mlAnomaly bool, mlConfidence float64) (Verdict, string) {
	// ------------------------------------------
	// 1. Critical Rules (The "Must Block" Layer)
	// ------------------------------------------
	if ruleBlock {
		return Block, "Critical Rule Match"
	}

	// If the rule score is huge, we don't even need ML.
	if ruleScore >= 15 {
		return Block, "High Risk Rule Score"
	}

	// ------------------------------------------
	// 2. ML / Hybrid Score Check (The "Smart" Layer)
	// ------------------------------------------
	// We use the raw 'mlConfidence' (Risk Score) to decide.

	// Case A: High Confidence Attack -> BLOCK
	// The Service.py sends us a hybrid score (ML + Heuristics).
	// If it's very high (> 0.75), we block.
	if mlConfidence > 0.75 {
		return Block, "AI/Hybrid Anomaly Detected"
	}

	// Case B: Medium Confidence -> MONITOR (Log but allow)
	// If score is between 0.50 and 0.75, it's suspicious.
	// We flag it for review but don't break the user experience.
	if mlConfidence > 0.50 {
		return Monitor, "Suspicious Activity (Medium Risk)"
	}

	// Case C: Low Confidence / Safe
	// We can still use ruleScore to tie-break if ML is unsure.
	if ruleScore >= 10 && mlConfidence > 0.40 {
		return Monitor, "Combined Rule+ML Suspicion"
	}

	return Allow, "Clean"
}