# Assess network and VoIP signaling, media, and management exposure

## Assess network and VoIP signaling, media, and management exposure

Owner configuration review, approved reachability observations, and consented synthetic calls. Distinguish Internet, user LAN, voice LAN, and management views. No interception of real calls, registration attacks, or call disruption.

VoIP has separate signaling, media, and management paths. Signaling authentication does not establish media confidentiality. TLS protecting SIP on one hop does not automatically protect other hops or the RTP media stream. Review each endpoint, proxy, gateway, and recording leg; a protected handset leg can coexist with an unprotected downstream leg.

Media protection needs negotiated encryption and integrity, validated peers, and an appropriate key-management policy. SRTP packets resemble RTP, so a port or packet appearance alone cannot establish negotiated protection. Dynamic media ranges and NAT complicate firewall policy; use the actual deployed ranges and peers, not the broad historical port lists in a book.

Historical references to SSLv3, TLSv1, old phone defaults, and vendor products are architectural context, not current configuration recommendations. Use currently supported vendor security profiles and organizational cryptographic policy; do not assume all modern SIP or IAX deployments share the books' defaults.

### Verify

1. Obtain a diagram of signaling/media/management flows with endpoint and proxy owners, allowed source networks, actual port ranges, certificate trust policy, and recording integrations.
2. Review authentication/authorization requirements for endpoint registration, call setup, management, and deregistration from configuration or existing test evidence. Do not issue unsolicited registrations or disconnect requests.
3. With consenting test endpoints place one normal synthetic call. Collect redacted endpoint/proxy session diagnostics showing negotiated signaling security, media protection, peer identity validation, and each traversed hop; do not record real conversation audio or key material.
4. Compare firewall/SBC rules with required peers and negotiated media ranges. Use existing approved connection evidence or tightly bounded service-discovery checks; UDP silence is not proof of closure.
5. Inspect whether endpoints require protected modes or silently allow unprotected fallback. Validate supplier-supported policy and logs; do not force a downgrade or replay media.

### Fix / prevent

1. Require current vendor-supported signaling security with peer/certificate validation on each required hop and appropriate authenticated media protection and key management.
2. Restrict management and signaling to intended peers; use reviewed SBC/firewall policies and the smallest supported media ranges. Segmentation alone does not encrypt voice.
3. Disable inappropriate cleartext fallback where supported and test interoperability, recording requirements, and emergency-call functionality through approved procedures.

### Retest

1. Repeat a consented synthetic call and confirm negotiated protection on every required leg and normal audio in both directions.
2. Reconcile access rules with allowed and denied sources and verify management isolation. Document gateways or endpoints that cannot meet policy rather than calling the whole deployment secure.

### Detection evidence

1. Monitor unexpected endpoint registrations, management changes, failed peer validation, and unprotected-mode negotiations without logging keys or conversation contents.
2. Correlate call quality and SBC/firewall errors after policy changes; network-security changes must not silently break availability.

### Decision branches

- **If Signaling is protected but media is unencrypted:** Report media confidentiality exposure from the relevant network vantage; signaling TLS is not the remedy for media.
- **If One proxy leg lacks protection or peer validation:** Report the specific hop and trust gap, not end-to-end security.
- **If Only a nominal secure port or SRTP-looking capture is available:** Protection remains unverified until negotiated session and configuration evidence agree.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-10]] (PDF page 196): Explains signaling TLS and certificate validation; obsolete protocol versions are explicitly not adopted.
- [[book-10]] (PDF page 197): States that TLS-protected signaling with cleartext RTP still exposes audio and distinguishes SRTP.
- [[book-10]] (PDF page 198): Notes that SRTP looks similar on the wire and distinguishes confidentiality from integrity.
- [[book-10]] (PDF page 202): Explains dynamic media port and NAT/firewall difficulties; historical broad ranges are not copied.
- [[book-10]] (PDF page 207): Audit questions distinguish session controls, directory protection, and media encryption.