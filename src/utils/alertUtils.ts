import type { SecurityAlert, AlertType, Severity } from '@/data/mockData';
import type { EmailAnalysisResult } from '@/services/claudeService';

/**
 * Derives a structured SecurityAlert from an EmailAnalysisResult.
 */
export function resultToAlert(r: EmailAnalysisResult): SecurityAlert {
  const score = r.threat_score ?? 0;
  const severity: Severity =
    score >= 85 ? 'critical' : score >= 65 ? 'high' : score >= 40 ? 'medium' : score >= 20 ? 'low' : 'info';

  let type: AlertType = 'Downgrade Attack';
  const verdictLow = (r.verdict ?? '').toLowerCase();
  const summaryLow = (r.summary ?? '').toLowerCase();

  if (verdictLow.includes('cipher') || summaryLow.includes('cipher') || summaryLow.includes('rc4') || summaryLow.includes('3des')) {
    type = 'Weak Cipher';
  } else if (verdictLow.includes('expired') || summaryLow.includes('expired') || summaryLow.includes('certificate')) {
    type = 'Expired Certificate';
  } else if (verdictLow.includes('key') || summaryLow.includes('1024') || summaryLow.includes('rsa-1024')) {
    type = 'Weak Key';
  } else if (verdictLow.includes('starttls') || summaryLow.includes('starttls') || summaryLow.includes('stripping')) {
    type = 'STARTTLS Stripping';
  } else if (verdictLow.includes('self-signed') || summaryLow.includes('self-signed')) {
    type = 'Self-Signed Certificate';
  } else if (verdictLow.includes('mitm') || summaryLow.includes('mitm') || summaryLow.includes('interception')) {
    type = 'MitM Detected';
  } else if (verdictLow.includes('protocol') || summaryLow.includes('protocol')) {
    type = 'Protocol Violation';
  } else {
    type = 'Downgrade Attack';
  }

  const fromHdr = r.headers?.find((h) => h.key.toLowerCase() === 'from')?.value ?? r.threat_intel?.domain ?? 'Unknown Sender';
  const detected = new Date().toISOString().replace('T', ' ').slice(0, 19);

  const observedFacts: string[] = [];
  if (r.threat_intel?.domain) observedFacts.push(`Sender domain: ${r.threat_intel.domain}`);
  if (r.threat_intel?.spf || r.threat_intel?.dkim || r.threat_intel?.dmarc) {
    observedFacts.push(`Authentication: SPF=${r.threat_intel.spf ?? 'N/A'}, DKIM=${r.threat_intel.dkim ?? 'N/A'}, DMARC=${r.threat_intel.dmarc ?? 'N/A'}`);
  }
  if (r.origin?.country) observedFacts.push(`Origin country: ${r.origin.country}`);
  observedFacts.push(`Risk score: ${score}/100`);
  if (r.risk_factors && r.risk_factors.length > 0) {
    r.risk_factors.slice(0, 2).forEach((rf) => observedFacts.push(`${rf.label}: ${rf.detail}`));
  }

  const aiInference =
    r.ai_inferences && r.ai_inferences.length > 0
      ? r.ai_inferences.map((i) => `${i.inference} (${i.confidence}% confidence)`).join('. ')
      : r.summary ?? `Threat classification: ${r.verdict} with ${r.confidence ?? score}% confidence.`;

  const relatedIndicators: string[] = [];
  if (r.threat_intel?.sending_ip) relatedIndicators.push(r.threat_intel.sending_ip);
  if (r.threat_intel?.domain) relatedIndicators.push(r.threat_intel.domain);
  if (r.threat_intel?.urls) r.threat_intel.urls.slice(0, 1).forEach((u) => u && relatedIndicators.push(u));

  const recommendedAction =
    r.recommended_actions && r.recommended_actions.length > 0
      ? `[${r.recommended_actions[0].priority.toUpperCase()}] ${r.recommended_actions[0].action}: ${r.recommended_actions[0].detail}`
      : 'Review email headers and block originating IP at the gateway.';

  return {
    id: `ALR-${r.case_id}`,
    severity,
    type,
    source: fromHdr,
    detected,
    status: severity === 'critical' || severity === 'high' ? 'new' : 'acknowledged',
    relatedCase: r.case_id,
    summary: r.summary ?? `Email analyzed by SENTINEL-X. Verdict: ${r.verdict}. Risk score ${score}/100.`,
    observedFacts,
    aiInference,
    relatedIndicators,
    relatedCampaign: r.campaign_id && r.campaign_id !== 'UNKNOWN' ? r.campaign_id : 'None',
    recommendedAction,
  };
}
