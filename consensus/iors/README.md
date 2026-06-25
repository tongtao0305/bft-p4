# IORS

IORS is the current prototype for identifying suspicious consensus traffic in the
data plane and exposing risk signals for scheduling or control-plane inspection.

The switch is intended to detect likely conflicts, such as repeated consensus
sequence numbers with different message digests. It does not make final Byzantine
fault decisions or replace endpoint-side protocol validation.
