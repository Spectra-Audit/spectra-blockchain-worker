---
name: summary-knowledge
description: Static knowledge base for the executive summary agent. Contains scoring interpretation rules, risk factor weights, and assessment guidelines.
---

## Scoring Dimensions & Interpretation

### Code Score (45% weight with token, 70% without)
- 90-100: Professional-grade audit, no significant issues
- 70-89: Minor issues found, well-audited codebase
- 50-69: Several medium findings, needs attention
- 30-49: Major vulnerabilities present, high risk
- 0-29: Critical vulnerabilities, unsafe to use

### Distribution Score (15% weight)
- 90-100: Excellent distribution, no concentration risk
- 70-89: Good distribution, minor concentration
- 50-69: Moderate concentration, some whale risk
- 30-49: High concentration, significant risk
- 0-29: Extreme concentration, very high risk

### Tokenomics Score (15% weight)
- 90-100: Sound tokenomics, sustainable model
- 70-89: Minor tokenomics concerns
- 50-69: Moderate concerns, some red flags
- 30-49: Significant issues, unsustainable elements
- 0-29: Critical tokenomics flaws

### Liquidity Score (15% weight)
- 90-100: Deep liquidity, multiple pairs, high TVL
- 70-89: Adequate liquidity for current usage
- 50-69: Limited liquidity, slippage risk
- 30-49: Thin liquidity, high slippage risk
- 0-29: Near-zero liquidity, exit risk

### Sentiment Score (10% weight, 30% without token)
- 90-100: Strong community trust, active engagement
- 70-89: Positive sentiment, good engagement
- 50-69: Mixed sentiment, some concerns
- 30-49: Negative sentiment, community distrust
- 0-29: Highly negative, active warnings

## Risk Escalation Rules

1. **Finding severity overrides score**: A single CRITICAL finding caps safety at LOW regardless of scores
2. **Multiple HIGH findings**: Three or more HIGH findings cap safety at LOW
3. **Zero liquidity + token project**: Always CRITICAL if project has a token but < $1K liquidity
4. **Creator holds > 50%**: Always LOW or CRITICAL regardless of code quality
5. **No code audit data**: Cap confidence at 0.5, note in project_notes

## Cross-Project Risk Patterns

### High-Risk Combinations
- Code < 50 + Token distribution < 40 = CRITICAL
- Liquidity < 30 + Distribution < 50 = CRITICAL (rug pull risk)
- Tokenomics < 40 + Sentiment < 30 = LOW (market rejection)
- Code < 60 + Liquidity < 40 = LOW (unverified + illiquid)

### Positive Indicators
- Code > 80 + all dimensions > 60 = HIGH candidate
- Liquidity > 70 + Distribution > 70 = Strong fundamentals
- Sentiment > 80 + growing followers = Community trust

## Assessment Tone Guidelines

- **For HIGH safety**: Professional, confident, acknowledge what's working
- **For MEDIUM safety**: Balanced, note strengths alongside concerns
- **For LOW safety**: Direct, focus on specific risks and remediation paths
- **For CRITICAL safety**: Urgent but factual, no alarmism — just clear risk communication

## Market Data Context

- **TVL < $10K**: Effectively no meaningful liquidity for a token project
- **Market Cap < $50K**: Micro-cap, extreme volatility risk
- **Volume/TVL ratio > 5**: High trading activity relative to TVL (potential volatility)
- **Volume/TVL ratio < 0.1**: Low interest or inactive market
- **Holder count < 100**: Very early stage or low adoption
- **Holder count > 10,000**: Meaningful adoption level
