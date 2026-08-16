---
"cypher-brain": patch
---

The `estimate_cost` MCP tool now describes the result shape it actually returns.
Since the fields became always-present-and-nullable, the description still told
agents that `usd_estimate` is omitted when no rate is available — so an agent
testing for the key's presence would read a failed rate lookup as a successful
one. The returned object is unchanged.
