<?php
/**
 * Phishing Detection Tool - Core Detection Logic
 * EDUCATIONAL / SCHOOL PROJECT USE ONLY
 *
 * This class compares two HTML pages (an "original" reference page and
 * a "suspect" page) and flags signs that the suspect page may be a
 * phishing clone of the original.
 *
 * Detection signals used:
 *  1. Content similarity (% match of HTML/text content)
 *  2. Domain mismatch (declared domain vs original domain)
 *  3. Lookalike domain detection (simple character substitution check)
 *  4. Suspicious form action URL (where login data would actually be sent)
 */

class PhishingDetector
{
    private string $originalHtml;
    private string $suspectHtml;

    public function __construct(string $originalHtml, string $suspectHtml)
    {
        $this->originalHtml = $originalHtml;
        $this->suspectHtml  = $suspectHtml;
    }

    /** Extract the declared domain from a <meta name="site-domain"> tag */
    public function extractDomain(string $html): ?string
    {
        if (preg_match('/<meta\s+name=["\']site-domain["\']\s+content=["\']([^"\']+)["\']/i', $html, $matches)) {
            return $matches[1];
        }
        return null;
    }

    /** Extract the form action URL, if any (where submitted data is sent) */
    public function extractFormAction(string $html): ?string
    {
        if (preg_match('/<form[^>]*action=["\']([^"\']*)["\']/i', $html, $matches)) {
            return $matches[1];
        }
        return null;
    }

    /** Calculate textual/structural similarity percentage between the two pages */
    public function calculateSimilarity(): float
    {
        similar_text($this->originalHtml, $this->suspectHtml, $percent);
        return round($percent, 2);
    }

    /**
     * Very simple lookalike-domain check: flags common homoglyph-style
     * substitutions often used in phishing domains (e.g. rn -> m, i -> l).
     */
    public function isLookalikeDomain(string $originalDomain, string $suspectDomain): bool
    {
        $normalize = function (string $domain): string {
            $domain = strtolower($domain);
            $domain = str_replace(['rn', '1', '0', 'i'], ['m', 'l', 'o', 'l'], $domain);
            return $domain;
        };

        if ($originalDomain === $suspectDomain) {
            return false; // identical domain, not a lookalike, not a mismatch
        }

        return $normalize($originalDomain) === $normalize($suspectDomain);
    }

    /** Run the full analysis and return a structured report */
    public function generateReport(): array
    {
        $originalDomain = $this->extractDomain($this->originalHtml) ?? 'unknown';
        $suspectDomain  = $this->extractDomain($this->suspectHtml) ?? 'unknown';
        $formAction     = $this->extractFormAction($this->suspectHtml) ?? 'none';

        $similarity   = $this->calculateSimilarity();
        $domainMatch  = ($originalDomain === $suspectDomain);
        $lookalike    = $this->isLookalikeDomain($originalDomain, $suspectDomain);

        $suspiciousFormAction = (
            $formAction !== 'none' &&
            stripos($formAction, $suspectDomain) === false &&
            stripos($formAction, $originalDomain) === false
        );

        // --- Risk scoring (simple weighted rule-based system) ---
        $riskScore = 0;
        if ($similarity > 80 && !$domainMatch) $riskScore += 50;
        if ($lookalike)                         $riskScore += 30;
        if ($suspiciousFormAction)              $riskScore += 20;

        if ($riskScore >= 50) {
            $verdict = 'PHISHING SUSPECTED';
        } elseif ($riskScore >= 20) {
            $verdict = 'SUSPICIOUS - REVIEW MANUALLY';
        } else {
            $verdict = 'LIKELY SAFE';
        }

        return [
            'original_domain'         => $originalDomain,
            'suspect_domain'          => $suspectDomain,
            'content_similarity'      => $similarity . '%',
            'domain_match'            => $domainMatch,
            'lookalike_domain'        => $lookalike,
            'suspect_form_action'     => $formAction,
            'suspicious_form_action'  => $suspiciousFormAction,
            'risk_score'              => $riskScore,
            'verdict'                 => $verdict,
        ];
    }
}
