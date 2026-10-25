# Splunk HEC documentation research

Research date: 2026-10-23. Target: Splunk Enterprise HEC setup and configuration.

## Evidence limitations

The librarian reported HTTP 403 when directly fetching the five requested resource links. The findings below summarize indexed official excerpts, not a full-page review. Treat this as preliminary guidance, not a verified configuration specification. The resolved links target Enterprise 10.6; compatibility with the deployed Splunk version has not been established.

## Requested sources and resolved references

1. [UseHECusingconffiles](https://help.splunk.com/en/?resourceId=Splunk_Data_UseHECusingconffiles) → [Configuration files](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/set-up-and-use-http-event-collector-with-configuration-files).
2. [HTTPEventCollectortokenmanagement](https://help.splunk.com/en/?resourceId=Splunk_Data_HTTPEventCollectortokenmanagement) → [Web setup and token management](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web).
3. [FormateventsforHTTPEventCollector](https://help.splunk.com/en/?resourceId=Splunk_Data_FormateventsforHTTPEventCollector) → [Event formatting](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector).
4. [HECExamples](https://help.splunk.com/en/?resourceId=Splunk_Data_HECExamples) → [Examples](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/http-event-collector-examples).
5. [TroubleshootHTTPEventCollector](https://help.splunk.com/en/?resourceId=Splunk_Data_TroubleshootHTTPEventCollector) → [Troubleshooting](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/troubleshoot-http-event-collector).

## Preliminary findings

- **Configuration:** `inputs.conf` separates global HTTP listener settings from token stanzas named `[http://<token_name>]`. Token settings include token value, enablement, and event metadata defaults. Prefer application `local` configuration over changing shipped defaults. Exact precedence, property lists, enablement semantics, and restart requirements need full-text verification. [1]
- **Authentication:** HEC uses tokens; examples use `Authorization: Splunk <TOKEN>`. Do not assume query-string authentication is enabled. Enterprise configuration-file controls must not be generalized to Splunk Cloud. [1, 2, 4]
- **Event format:** `/services/collector/event` accepts JSON event envelopes; `/services/collector/raw` accepts raw content. Envelope metadata includes `time`, `host`, `source`, `sourcetype`, `index`, and `fields`, alongside `event`. Token defaults supply omitted metadata where applicable. Multiple envelopes can be concatenated rather than wrapped in a JSON array. [3, 4]
- **Acknowledgments:** Indexer acknowledgment depends on configuration and requires channel handling and acknowledgment polling. A successful HTTP response alone does not establish durable indexing. Exact raw-channel requirements and acknowledgment semantics remain to be checked in full documentation. [3, 4]
- **Troubleshooting:** Distinguish listener access, TLS, authentication/token state, payload validity, index selection, and ingestion results. Exact response-code tables and diagnostic log locations remain unverified. [5]

## Illustrative request

This is a placeholder-only illustration derived from the reported endpoint and header conventions, not a verbatim verified documentation example. Use a trusted certificate; do not disable TLS verification.

```sh
curl --url 'https://<HEC_HOST>:<HEC_PORT>/services/collector/event' \
  --header 'Authorization: Splunk <HEC_TOKEN>' \
  --header 'Content-Type: application/json' \
  --data '{"event":"HEC validation canary","sourcetype":"manual_hec_check"}'
```

Do not run against a live range without authorization. Real tokens must not enter committed notes or command transcripts.

## Implications for this repository

Engineering inference: process readiness and TCP readiness are useful gates, but neither proves TLS correctness, valid authentication, payload acceptance, indexing, or acknowledgment completion. The independently diagnosed post-restart process race does not establish HEC ingestion health or explain the separate KV-store errors. No runtime probes were performed as part of this research.

## Follow-up verification

Retrieve the full official pages before relying on exact property values, restart behavior, response codes, raw-channel rules, configuration precedence, or Cloud differences. Match documentation to the installed product/version. This research did not change any role, configuration, or deployed service.
