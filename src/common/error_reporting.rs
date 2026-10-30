use std::time::Duration;

use common::defaults::APP_USER_AGENT;
use serde_json::json;

pub struct ErrorReporter;

impl ErrorReporter {
    fn get_url() -> String {
        if cfg!(debug_assertions) {
            "https://staging-telemetry.qdrant.io".to_string()
        } else {
            "https://telemetry.qdrant.io".to_string()
        }
    }

    /// Build serialized JSON payload for telemetry error reporting.
    fn build_report_payload(error: &str, reporting_id: &str, backtrace: Option<&str>) -> String {
        let error = redact_crypto_material_for_report(error);
        let backtrace = backtrace.map(redact_crypto_material_for_report);
        let report = json!({
            "id": reporting_id,
            "error": error,
            "backtrace": backtrace.as_deref(),
        });
        report.to_string()
    }

    pub fn report(error: &str, reporting_id: &str, backtrace: Option<&str>) {
        Self::report_to_url(error, reporting_id, backtrace, &Self::get_url());
    }

    fn report_to_url(error: &str, reporting_id: &str, backtrace: Option<&str>, url: &str) {
        let client = match reqwest::blocking::Client::builder()
            .user_agent(APP_USER_AGENT.as_str())
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                log::warn!("Failed to build telemetry reporter client: {err}");
                return;
            }
        };

        let data = Self::build_report_payload(error, reporting_id, backtrace);

        if let Err(err) = client
            .post(url)
            .body(data)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(1))
            .send()
        {
            log::debug!("Telemetry panic report was not sent: {err}");
        }
    }
}

pub(crate) fn redact_crypto_material_for_report(value: &str) -> String {
    let compact = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let contains_crypto_material = [
        "qdrantsec",
        "qdrantclientaead",
        "qdrantsecvectors",
        "ciphertext",
        "encryptedquery",
        "accesstoken",
        "authorization",
        "bearer",
        "apikey",
        "accesskeyid",
        "awssessiontoken",
        "awssecuritytoken",
        "clientsecret",
        "contextdigest",
        "cryptocontext",
        "cryptocontextb64",
        "cookie",
        "credential",
        "credentials",
        "idtoken",
        "jwt",
        "materialfingerprint",
        "password",
        "publickey",
        "publickeys",
        "publickeysb64",
        "publickeyb64",
        "refreshtoken",
        "secretb64",
        "setcookie",
        "wrappedkey",
        "valueb64",
        "valuesb64",
        "nonceb64",
        "signatureb64",
        "signaturepublickey",
        "signaturepublickeyb64",
        "signaturepublickeys",
        "signaturepublickeysb64",
        "signaturesig",
        "sigb64",
        "privatekey",
        "secretaccesskey",
        "secretkey",
        "securitytoken",
        "sessiontoken",
        "vaulttoken",
        "xamzcredential",
        "xamzsignature",
        "xamzsecuritytoken",
        "xapikey",
        "accessedleaflabel",
        "accessedleaflabels",
        "accesscount",
        "accesscounts",
        "accessvolume",
        "accessvolumes",
        "accessvolumecount",
        "accessvolumecounts",
        "accessvolumelen",
        "accessvolumelength",
        "accessvolumelengths",
        "accesspath",
        "accesspaths",
        "blockplaintext",
        "blockplaintexts",
        "blindresult",
        "blindresultkey",
        "bucketaead",
        "bucketaeadkey",
        "bucketcommitment",
        "bucketcommitments",
        "bucketid",
        "bucketids",
        "bucketidcount",
        "bucketidcounts",
        "bucketidsequence",
        "bucketidsequences",
        "bucketplaintext",
        "bucketplaintexts",
        "bucketsequence",
        "bucketsequences",
        "candidateheap",
        "candidateid",
        "candidateids",
        "candidatenode",
        "candidatenodes",
        "candidatescore",
        "candidatescores",
        "candidatedistance",
        "candidatedistances",
        "clientid",
        "clientids",
        "clientsignature",
        "clientstate",
        "clientstates",
        "clientstatebackup",
        "clientstatebackups",
        "clientstateciphertext",
        "clientstateciphertexts",
        "clientstateciphertexthash",
        "clientstateciphertexthashes",
        "clientstateciphertextsha256",
        "clientstateciphertextssha256",
        "clientstatekey",
        "clientstatesnapshot",
        "clientstatesnapshots",
        "clientrecoverystate",
        "clientrecoverystates",
        "clientrecoverystatebackup",
        "clientrecoverystatebackups",
        "clientrecoverystatedigest",
        "clientrecoverystatedigests",
        "commitsignature",
        "distance",
        "distances",
        "distancescore",
        "distancescores",
        "entrynodeid",
        "entrynodeids",
        "encryptedclientstate",
        "encryptedclientstates",
        "encryptedclientstatebackup",
        "encryptedclientstatebackups",
        "encryptedclientstatesnapshot",
        "encryptedclientstatesnapshots",
        "encryptedclientstateciphertext",
        "encryptedclientstateciphertexts",
        "encryptedclientstateciphertexthash",
        "encryptedclientstateciphertexthashes",
        "encryptedclientstateciphertextsha256",
        "encryptedclientstateciphertextssha256",
        "encryptedqueries",
        "encryptedqueriesb64",
        "fetchtoken",
        "fetchtokens",
        "hitcount",
        "hitcounts",
        "keymaterial",
        "keymaterialb64",
        "leafcommitment",
        "leafcommitments",
        "leafcount",
        "leafcounts",
        "leafhash",
        "leafhashes",
        "leafid",
        "leafids",
        "leaflabel",
        "leaflabels",
        "levelmask",
        "levelmasks",
        "manifestsignature",
        "masterkey",
        "masterkeyb64",
        "materialb64",
        "merkleproof",
        "merkleproofs",
        "neighbor",
        "neighbors",
        "neighborcount",
        "neighborcounts",
        "neighborid",
        "neighborids",
        "neighborlevel",
        "neighborlevels",
        "nodeblock",
        "nodeblocks",
        "nodeaead",
        "nodeaeadkey",
        "nodeid",
        "nodeids",
        "nodeplaintext",
        "nodeplaintexts",
        "nodescore",
        "nodescores",
        "nodedistance",
        "nodedistances",
        "nonces",
        "noncesb64",
        "newleaf",
        "newleaves",
        "newleafid",
        "newleafids",
        "oldleaf",
        "oldleaves",
        "oldleafid",
        "oldleafids",
        "operationtoken",
        "operationtokens",
        "orampath",
        "orampaths",
        "orampositionmap",
        "orampositionmapbackup",
        "orampositionmapbackups",
        "orampositionmaps",
        "orampositionmapsnapshot",
        "orampositionmapsnapshots",
        "ownersigningkeyid",
        "ownersigningkeyids",
        "payloadbytes",
        "payloadtoken",
        "payloadtokenkey",
        "payloadtokens",
        "payloadlen",
        "payloadlength",
        "payloadplaintext",
        "payloadplaintexts",
        "paths",
        "pathcount",
        "pathcounts",
        "pathlabel",
        "pathlabels",
        "plaintextblock",
        "plaintextblocks",
        "plaintextbucket",
        "plaintextbuckets",
        "plaintextpayload",
        "plaintextpayloads",
        "plaintextvector",
        "plaintextvectors",
        "positioncount",
        "positioncounts",
        "positionmap",
        "positionmapbackup",
        "positionmapbackups",
        "positionmaplen",
        "positionmaplength",
        "positionmaps",
        "positionmapsnapshot",
        "positionmapsnapshots",
        "proof",
        "proofs",
        "proofvalue",
        "proofvalues",
        "queryembedding",
        "queryembeddings",
        "queryplaintext",
        "queryplaintexts",
        "queryvector",
        "queryvectors",
        "payloadfetchtoken",
        "payloadfetchtokens",
        "payloadoramleaf",
        "payloadoramleaves",
        "pointtoken",
        "pointtokens",
        "readbucket",
        "readbucketcount",
        "readbucketcounts",
        "readbucketid",
        "readbucketidcount",
        "readbucketidcounts",
        "readbucketids",
        "readbucketidsequence",
        "readbucketidsequences",
        "readbucketsequence",
        "readbucketsequences",
        "readbuckets",
        "readpath",
        "readpathlabel",
        "readpaths",
        "readsignature",
        "requestsignature",
        "requestedbucketcount",
        "requestedbucketcounts",
        "requestedpathcount",
        "requestedpathcounts",
        "resourcekey",
        "resourcekeyb64",
        "rootkey",
        "rootkeyb64",
        "returnedbucketcount",
        "returnedbucketcounts",
        "resultcount",
        "resultcounts",
        "resultid",
        "resultids",
        "realpathcount",
        "realpathcounts",
        "roothash",
        "roothashes",
        "oldroothash",
        "newroothash",
        "score",
        "scores",
        "sessionid",
        "signaturesb64",
        "signingkeyid",
        "signingkeyids",
        "sibling",
        "siblings",
        "siblingcount",
        "siblingcounts",
        "siblinghash",
        "siblinghashes",
        "stash",
        "stashbackup",
        "stashbackups",
        "stashlen",
        "stashlength",
        "stashsnapshot",
        "stashsnapshots",
        "stateciphertext",
        "stateciphertexts",
        "stateciphertexthash",
        "stateciphertexthashes",
        "stateciphertextsha256",
        "stateciphertextssha256",
        "tokencount",
        "tokencounts",
        "tokenmap",
        "tokenmapbackup",
        "tokenmapbackups",
        "tokenmaps",
        "tokenmapsnapshot",
        "tokenmapsnapshots",
        "tokenpositionmap",
        "tokenpositionmapbackup",
        "tokenpositionmapbackups",
        "tokenpositionmaps",
        "tokenpositionmapsnapshot",
        "tokenpositionmapsnapshots",
        "topk",
        "updatedbucket",
        "updatedbucketcommitment",
        "updatedbucketcommitments",
        "updatedbucketcount",
        "updatedbucketcounts",
        "updatedbucketid",
        "updatedbucketids",
        "updatedbuckets",
        "unknownfield",
        "vectorbytes",
        "vectorplaintext",
        "vectorplaintexts",
        "visitednode",
        "visitednodes",
        "visitednodeid",
        "visitednodeids",
        "wrappedresourcekey",
        "wrappedresourcekeyb64",
        "wrappingkey",
        "wrappingkeyb64",
        "writebackbucketcount",
        "writebackbucketcounts",
    ]
    .iter()
    .any(|needle| compact.contains(needle));

    if contains_crypto_material {
        "[redacted: crypto material omitted from telemetry report]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::ErrorReporter;

    #[test]
    /// Ensure panic report payload contains the expected fields.
    fn test_build_report_payload_with_backtrace() {
        let payload = ErrorReporter::build_report_payload("panic", "node-1", Some("bt-line"));

        assert!(payload.contains("\"id\":\"node-1\""));
        assert!(payload.contains("\"error\":\"panic\""));
        assert!(payload.contains("\"backtrace\":\"bt-line\""));
    }

    #[test]
    /// Missing backtrace must serialize as null.
    fn test_build_report_payload_without_backtrace() {
        let payload = ErrorReporter::build_report_payload("panic", "node-2", None);

        assert!(payload.contains("\"id\":\"node-2\""));
        assert!(payload.contains("\"error\":\"panic\""));
        assert!(payload.contains("\"backtrace\":null"));
    }

    #[test]
    fn test_build_report_payload_redacts_crypto_material() {
        let payload = ErrorReporter::build_report_payload(
            r#"panic while handling {"$qdrant_sec":{"envelope":{"nonce":"nonce-sentinel","ciphertext":"ciphertext-sentinel"}}}"#,
            "node-3",
            Some("frame with wrappedKeyB64=wrapped-sentinel and x-vault-token=token"),
        );

        assert!(payload.contains("crypto material omitted"));
        assert!(!payload.contains("$qdrant_sec"));
        assert!(!payload.contains("nonce-sentinel"));
        assert!(!payload.contains("ciphertext-sentinel"));
        assert!(!payload.contains("wrapped-sentinel"));
        assert!(!payload.contains("x-vault-token"));
    }

    #[test]
    fn test_build_report_payload_redacts_private_result_and_recovery_fixture_sentinels() {
        let result_payload = "qsec-v2-private-result-payload-3f7a9c";
        let client_recovery_payload = "qsec-v2-client-recovery-state-payload-8d4c1a";
        let report = ErrorReporter::build_report_payload(
            &format!(r#"payload_plaintext={{"body":"{result_payload}"}}"#),
            "node-private-oram-leakage-gate",
            Some(&format!(
                "client_recovery_state={{\"stash\":\"{client_recovery_payload}\"}}"
            )),
        );

        assert!(report.contains("crypto material omitted"));
        assert!(!report.contains(result_payload));
        assert!(!report.contains(client_recovery_payload));
    }

    #[test]
    fn test_panic_report_transport_body_redacts_private_oram_fixture_sentinels() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "panic report request timed out");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("failed to accept panic report request: {err}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let (header_end, content_length) = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "panic report request ended before its body");
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .expect("panic report request must include content-length");
                break (header_end + 4, content_length);
            };
            while request.len() < header_end + content_length {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "panic report request body was truncated");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            String::from_utf8(request[header_end..header_end + content_length].to_vec()).unwrap()
        });

        let result_payload = "qsec-v2-private-result-payload-3f7a9c";
        let client_recovery_payload = "qsec-v2-client-recovery-state-payload-8d4c1a";
        ErrorReporter::report_to_url(
            &format!(r#"payload_plaintext={{"body":"{result_payload}"}}"#),
            "node-private-oram-transport-gate",
            Some(&format!(
                "client_recovery_state={{\"stash\":\"{client_recovery_payload}\"}}"
            )),
            &format!("http://{address}"),
        );
        let body = server.join().unwrap();

        assert!(body.contains("crypto material omitted"));
        assert!(!body.contains(result_payload));
        assert!(!body.contains(client_recovery_payload));
    }

    #[test]
    fn test_build_report_payload_redacts_aws_and_auth_spellings() {
        for secret in [
            "Authorization: Bearer authorization-sentinel",
            "Bearer bearer-token-sentinel",
            "api_key=api-key-sentinel",
            "apiKey=api-key-sentinel",
            "X-Amz-Security-Token: aws-token-sentinel",
            "access_token=access-token-sentinel",
            "refreshToken=refresh-token-camel-sentinel",
            "id_token=id-token-sentinel",
            "jwt=jwt-sentinel",
            "Cookie: cookie-sentinel",
            "set_cookie=set-cookie-sentinel",
            "Set-Cookie: set-cookie-header-sentinel",
            "session_token=session-token-sentinel",
            "sessionToken=session-token-sentinel",
            "cryptoContextB64=crypto-context-sentinel",
            "public_keys=[public-key-list-sentinel]",
            "publicKeyB64=public-key-sentinel",
            "publicKeysB64=[public-key-b64-list-sentinel]",
            "signature_public_key_b64=signature-public-key-b64-sentinel",
            "signaturePublicKeysB64=[signature-public-key-b64-list-sentinel]",
            "signature.sig=sig-sentinel",
            "secret_b64=generic-secret-b64-sentinel",
            "key_material=key-material-sentinel",
            "keyMaterialB64=key-material-b64-camel-sentinel",
            "master_key=master-key-sentinel",
            "masterKeyB64=master-key-b64-camel-sentinel",
            "material_b64=material-b64-sentinel",
            "resource_key=resource-key-sentinel",
            "resourceKeyB64=resource-key-b64-camel-sentinel",
            "root_key=root-key-sentinel",
            "rootKeyB64=root-key-b64-camel-sentinel",
            "wrapped_resource_key=wrapped-resource-key-sentinel",
            "wrappedResourceKeyB64=wrapped-resource-key-b64-camel-sentinel",
            "wrapping_key=wrapping-key-sentinel",
            "wrappingKeyB64=wrapping-key-b64-camel-sentinel",
            "AWS_ACCESS_KEY_ID=access-key-sentinel",
            "AWS_SECRET_ACCESS_KEY=secret-key-sentinel",
            "X-Amz-Credential=credential-sentinel",
            "X-Amz-Signature=signature-sentinel",
            "Security-Token: security-token-sentinel",
            "client_secret=client-secret-sentinel",
            "credential=generic-credential-sentinel",
            "credentials=[generic-credentials-sentinel]",
            "password=password-sentinel",
            "values_b64=[inline-values-b64-sentinel]",
            "encrypted_queries=[encrypted-queries-sentinel]",
            "encryptedQueriesB64=[encrypted-queries-b64-camel-sentinel]",
            "nonces=[nonces-list-sentinel]",
            "nonces_b64=[nonces-b64-list-sentinel]",
            "signatures_b64=[signatures-b64-list-sentinel]",
            "node_aead=node-aead-key-sentinel",
            "nodeAeadKey=node-aead-key-camel-sentinel",
            "bucket_aead=bucket-aead-key-sentinel",
            "bucketAeadKey=bucket-aead-key-camel-sentinel",
            "payload_token=payload-token-key-sentinel",
            "payloadTokenKey=payload-token-key-camel-sentinel",
            "blind_result=blind-result-key-sentinel",
            "blindResultKey=blind-result-key-camel-sentinel",
            "client_state_key=client-state-key-sentinel",
            "clientStateKey=client-state-key-camel-sentinel",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-4", Some(secret));

            assert!(payload.contains("crypto material omitted"), "{payload}");
            assert!(!payload.contains("sentinel"), "{payload}");
        }
    }

    #[test]
    fn test_build_report_payload_redacts_private_oram_access_pattern_fields() {
        for secret in [
            "session_id=private-session-sentinel",
            "sessionId=private-session-camel-sentinel",
            "session_ids=[private-session-list-sentinel]",
            "sessionIds=[private-session-list-camel-sentinel]",
            "client_id=private-client-id-sentinel",
            "clientIds=[private-client-ids-camel-sentinel]",
            "access_count=private-access-count-sentinel",
            "access.count=private-access-count-dot-sentinel",
            "access_counts=[private-access-counts-snake-sentinel]",
            "access.counts=[private-access-counts-dot-sentinel]",
            "accessCount=private-access-count-camel-sentinel",
            "accessCounts=[private-access-counts-camel-sentinel]",
            "access_volume=private-access-volume-snake-sentinel",
            "access.volume=private-access-volume-dot-sentinel",
            "access_volumes=[private-access-volumes-snake-sentinel]",
            "access.volumes=[private-access-volumes-dot-sentinel]",
            "accessVolume=private-access-volume-camel-sentinel",
            "accessVolumes=[private-access-volumes-camel-sentinel]",
            "access_volume_count=private-access-volume-count-snake-sentinel",
            "access.volume.count=private-access-volume-count-dot-sentinel",
            "access_volume_counts=[private-access-volume-counts-snake-sentinel]",
            "access.volume.counts=[private-access-volume-counts-dot-sentinel]",
            "accessVolumeCounts=[private-access-volume-counts-camel-sentinel]",
            "access_volume_len=private-access-volume-len-snake-sentinel",
            "access.volume.len=private-access-volume-len-dot-sentinel",
            "access_volume_length=private-access-volume-length-snake-sentinel",
            "access.volume.length=private-access-volume-length-dot-sentinel",
            "accessVolumeLength=private-access-volume-length-camel-sentinel",
            "access_volume_lengths=[private-access-volume-lengths-snake-sentinel]",
            "access.volume.lengths=[private-access-volume-lengths-dot-sentinel]",
            "accessVolumeLengths=[private-access-volume-lengths-camel-sentinel]",
            "path_count=private-path-count-sentinel",
            "path.count=private-path-count-dot-sentinel",
            "pathCounts=[private-path-counts-camel-sentinel]",
            "read_bucket_count=private-read-bucket-count-sentinel",
            "readBucketCounts=[private-read-bucket-counts-camel-sentinel]",
            "read_bucket_id_count=private-read-bucket-id-count-sentinel",
            "readBucketIdCounts=[private-read-bucket-id-counts-camel-sentinel]",
            "requested_path_count=private-requested-path-count-sentinel",
            "requested.path.count=private-requested-path-count-dot-sentinel",
            "requestedPathCounts=[private-requested-path-counts-camel-sentinel]",
            "requested_bucket_count=private-requested-bucket-count-sentinel",
            "requestedBucketCounts=[private-requested-bucket-counts-camel-sentinel]",
            "returned_bucket_count=private-returned-bucket-count-sentinel",
            "returnedBucketCounts=[private-returned-bucket-counts-camel-sentinel]",
            "updated_bucket_count=private-updated-bucket-count-sentinel",
            "updatedBucketCounts=[private-updated-bucket-counts-camel-sentinel]",
            "writeback_bucket_count=private-writeback-bucket-count-sentinel",
            "writebackBucketCounts=[private-writeback-bucket-counts-camel-sentinel]",
            "leaf_count=private-leaf-count-sentinel",
            "leafCounts=[private-leaf-counts-camel-sentinel]",
            "sibling_count=private-sibling-count-sentinel",
            "siblingCounts=[private-sibling-counts-camel-sentinel]",
            "position_count=private-position-count-sentinel",
            "positionCounts=[private-position-counts-camel-sentinel]",
            "position_map_len=private-position-map-len-sentinel",
            "positionMapLength=private-position-map-length-camel-sentinel",
            "stash_len=private-stash-len-sentinel",
            "stashLength=private-stash-length-camel-sentinel",
            "token_count=private-token-count-sentinel",
            "tokenCounts=[private-token-counts-camel-sentinel]",
            "neighbor_count=private-neighbor-count-sentinel",
            "neighborCounts=[private-neighbor-counts-camel-sentinel]",
            "payload_len=private-payload-len-sentinel",
            "payload.len=private-payload-len-dot-sentinel",
            "payloadLength=private-payload-length-camel-sentinel",
            "hit_count=private-hit-count-sentinel",
            "hitCounts=[private-hit-counts-camel-sentinel]",
            "result_count=private-result-count-sentinel",
            "resultCounts=[private-result-counts-camel-sentinel]",
            "real_path_count=private-real-path-count-sentinel",
            "real.path.count=private-real-path-count-dot-sentinel",
            "realPathCounts=[private-real-path-counts-camel-sentinel]",
            "path_label=private-path-label-sentinel",
            "path.label=private-path-label-dot-sentinel",
            "pathLabel=private-path-label-camel-sentinel",
            "paths=[private-raw-path-sentinel]",
            "access_path=[private-access-path-sentinel]",
            "accessPaths=[private-access-path-camel-sentinel]",
            "read_path=[private-single-read-path-sentinel]",
            "readPath=[private-single-read-path-camel-sentinel]",
            "read_paths=[private-read-path-sentinel]",
            "read_path_label=private-read-path-label-snake-sentinel",
            "read.path.label=private-read-path-label-dot-sentinel",
            "readPathLabel=private-read-path-label-camel-sentinel",
            "read_path_labels=[private-read-path-labels-snake-sentinel]",
            "read.path.labels=[private-read-path-labels-dot-sentinel]",
            "read_buckets=[private-read-bucket-sentinel]",
            "readBuckets=[private-read-bucket-camel-sentinel]",
            "read_bucket_id=private-single-read-bucket-sentinel",
            "read.bucket.id=private-single-read-bucket-dot-sentinel",
            "readBucketId=private-single-read-bucket-camel-sentinel",
            "read_bucket_ids=[private-read-bucket-id-sentinel]",
            "read.bucket.ids=[private-read-bucket-id-dot-sentinel]",
            "readBucketIds=[private-read-bucket-id-camel-sentinel]",
            "read_bucket_id_sequence=[private-read-bucket-sequence-sentinel]",
            "read.bucket.id.sequence=[private-read-bucket-sequence-dot-sentinel]",
            "readBucketIdSequence=[private-read-bucket-sequence-camel-sentinel]",
            "read_bucket_id_sequences=[private-read-bucket-sequences-sentinel]",
            "read_bucket_sequence=[private-read-bucket-sequence-short-sentinel]",
            "readBucketSequence=[private-read-bucket-sequence-short-camel-sentinel]",
            "read_bucket_sequences=[private-read-bucket-sequences-short-sentinel]",
            "readBucketSequences=[private-read-bucket-sequences-short-camel-sentinel]",
            "bucket_id_sequence=[private-bucket-sequence-snake-sentinel]",
            "bucket.id.sequence=[private-bucket-sequence-dot-sentinel]",
            "bucketIdSequence=[private-bucket-sequence-camel-sentinel]",
            "bucketIdSequences=[private-bucket-sequences-camel-sentinel]",
            "bucket_sequence=[private-bucket-sequence-short-snake-sentinel]",
            "bucket.sequence=[private-bucket-sequence-short-dot-sentinel]",
            "bucketSequence=[private-bucket-sequence-short-camel-sentinel]",
            "bucket_sequences=[private-bucket-sequences-short-snake-sentinel]",
            "bucketSequences=[private-bucket-sequences-short-camel-sentinel]",
            "pathLabels=[private-path-labels-camel-sentinel]",
            "readPathLabels=[private-read-path-labels-camel-sentinel]",
            "leaf_label=private-leaf-label-snake-sentinel",
            "leaf.label=private-leaf-label-dot-sentinel",
            "leafLabels=[private-leaf-label-sentinel]",
            "leaf_id=private-leaf-id-sentinel",
            "leafIds=[private-leaf-ids-camel-sentinel]",
            "old_leaf=private-old-leaf-sentinel",
            "oldLeaves=[private-old-leaves-camel-sentinel]",
            "old_leaf_id=private-old-leaf-id-sentinel",
            "oldLeafIds=[private-old-leaf-ids-camel-sentinel]",
            "new_leaf=private-new-leaf-sentinel",
            "newLeaves=[private-new-leaves-camel-sentinel]",
            "new_leaf_id=private-new-leaf-id-sentinel",
            "newLeafIds=[private-new-leaf-ids-camel-sentinel]",
            "leaf_commitment=private-single-leaf-commitment-sentinel",
            "leaf_commitments=[private-leaf-commitment-sentinel]",
            "leafCommitment=private-single-leaf-commitment-camel-sentinel",
            "leafCommitments=[private-leaf-commitment-camel-sentinel]",
            "leaf_hash=private-leaf-hash-sentinel",
            "leafHash=private-leaf-hash-camel-sentinel",
            "merkle_proof=private-merkle-proof-sentinel",
            "merkleProof=private-merkle-proof-camel-sentinel",
            "proof=private-proof-sentinel",
            "proofs=[private-proofs-sentinel]",
            "proof_value=private-proof-value-sentinel",
            "proof.value=private-proof-value-dot-sentinel",
            "proofValue=private-proof-value-camel-sentinel",
            "proof_values=[private-proof-values-sentinel]",
            "proof.values=[private-proof-values-dot-sentinel]",
            "sibling=private-sibling-sentinel",
            "siblings=[private-siblings-sentinel]",
            "sibling_hash=private-sibling-hash-sentinel",
            "siblingHash=private-sibling-hash-camel-sentinel",
            "accessed_leaf_labels=[private-accessed-leaf-sentinel]",
            "accessed.leaf.labels=[private-accessed-leaf-dot-sentinel]",
            "accessedLeafLabel=private-accessed-leaf-camel-singular-sentinel",
            "oram_path=[private-oram-path-sentinel]",
            "oramPaths=[private-oram-path-camel-sentinel]",
            "bucket_plaintext=private-bucket-plaintext-sentinel",
            "bucketPlaintext=private-bucket-plaintext-camel-sentinel",
            "plaintext_bucket=private-plaintext-bucket-sentinel",
            "plaintextBucket=private-plaintext-bucket-camel-sentinel",
            "bucket_id=private-bucket-sentinel",
            "bucket_ids=[private-bucket-list-sentinel]",
            "bucketIds=[private-bucket-list-camel-sentinel]",
            "bucketId=private-bucket-camel-singular-sentinel",
            "bucket_commitment=private-bucket-commitment-sentinel",
            "bucket.commitment=private-bucket-commitment-dot-sentinel",
            "bucket_commitments=[private-bucket-commitment-snake-plural-sentinel]",
            "bucket.commitments=[private-bucket-commitment-dot-plural-sentinel]",
            "bucketCommitments=[private-bucket-commitment-camel-sentinel]",
            "bucketCommitment=private-bucket-commitment-camel-singular-sentinel",
            "ciphertext_sha256=private-ciphertext-sha256-sentinel",
            "ciphertextSha256=private-ciphertext-sha256-camel-sentinel",
            "ciphertexts_sha256=[private-ciphertexts-sha256-sentinel]",
            "ciphertextsSha256=[private-ciphertexts-sha256-camel-sentinel]",
            "block_plaintext=private-block-plaintext-sentinel",
            "blockPlaintext=private-block-plaintext-camel-sentinel",
            "plaintext_block=private-plaintext-block-sentinel",
            "plaintextBlock=private-plaintext-block-camel-sentinel",
            "node_id=private-node-singular-sentinel",
            "node.id=private-node-dot-singular-sentinel",
            "node_ids=[private-node-sentinel]",
            "node.ids=[private-node-dot-sentinel]",
            "nodeId=private-node-camel-singular-sentinel",
            "nodeIds=[private-node-camel-sentinel]",
            "node_block=private-node-block-sentinel",
            "nodeBlock=private-node-block-camel-sentinel",
            "node_plaintext=private-node-plaintext-sentinel",
            "nodePlaintext=private-node-plaintext-camel-sentinel",
            "entry_node_id=private-entry-node-sentinel",
            "entry.node.id=private-entry-node-dot-sentinel",
            "entryNodeId=private-entry-node-camel-sentinel",
            "level_mask=private-level-mask-sentinel",
            "levelMask=private-level-mask-camel-sentinel",
            "visited_node_id=private-visited-node-singular-sentinel",
            "visited.node.id=private-visited-node-dot-singular-sentinel",
            "visited_node_ids=[private-visited-node-sentinel]",
            "visited.node.ids=[private-visited-node-dot-sentinel]",
            "visitedNodeId=private-visited-node-camel-singular-sentinel",
            "visitedNodeIds=[private-visited-node-camel-sentinel]",
            "neighbor_id=private-neighbor-singular-sentinel",
            "neighbor_ids=[private-neighbor-sentinel]",
            "neighborId=private-neighbor-camel-singular-sentinel",
            "neighborIds=[private-neighbor-camel-sentinel]",
            "neighborLevel=private-neighbor-level-camel-sentinel",
            "neighbor_levels=[private-neighbor-level-sentinel]",
            "neighbors=[private-neighbors-sentinel]",
            "candidate_heap=private-candidate-sentinel",
            "candidate.heap=private-candidate-dot-sentinel",
            "candidateHeap=private-candidate-camel-sentinel",
            "candidate_nodes=[private-candidate-node-sentinel]",
            "candidateNodes=[private-candidate-node-camel-sentinel]",
            "candidate_score=private-candidate-score-sentinel",
            "candidate.score=private-candidate-score-dot-sentinel",
            "candidate.scores=[private-candidate-scores-dot-sentinel]",
            "candidateScores=[private-candidate-scores-camel-sentinel]",
            "candidate_distance=private-candidate-distance-sentinel",
            "candidate.distance=private-candidate-distance-dot-sentinel",
            "candidate.distances=[private-candidate-distances-dot-sentinel]",
            "candidateDistances=[private-candidate-distances-camel-sentinel]",
            "score=private-score-sentinel",
            "scores=[private-scores-sentinel]",
            "distance=private-distance-sentinel",
            "distances=[private-distances-sentinel]",
            "distance_score=private-distance-score-sentinel",
            "distance.score=private-distance-score-dot-sentinel",
            "distance.scores=[private-distance-scores-dot-sentinel]",
            "distanceScores=[private-distance-scores-camel-sentinel]",
            "node_score=private-node-score-sentinel",
            "node.score=private-node-score-dot-sentinel",
            "node.scores=[private-node-scores-dot-sentinel]",
            "nodeScores=[private-node-scores-camel-sentinel]",
            "node_distance=private-node-distance-sentinel",
            "node.distance=private-node-distance-dot-sentinel",
            "node.distances=[private-node-distances-dot-sentinel]",
            "nodeDistances=[private-node-distances-camel-sentinel]",
            "query_vector=[private-query-vector-sentinel]",
            "query.vector=[private-query-vector-dot-sentinel]",
            "query.vectors=[private-query-vectors-dot-sentinel]",
            "queryVector=[private-query-vector-camel-sentinel]",
            "query_embedding=[private-query-embedding-sentinel]",
            "query.embedding=[private-query-embedding-dot-sentinel]",
            "query.embeddings=[private-query-embeddings-dot-sentinel]",
            "queryEmbeddings=[private-query-embeddings-camel-sentinel]",
            "query_plaintext=private-query-plaintext-sentinel",
            "query.plaintext=private-query-plaintext-dot-sentinel",
            "query.plaintexts=[private-query-plaintexts-dot-sentinel]",
            "queryPlaintext=private-query-plaintext-camel-sentinel",
            "client_signature=private-client-signature-sentinel",
            "client.signature=private-client-signature-dot-sentinel",
            "clientSignature=private-client-signature-camel-sentinel",
            "commit_signature=private-commit-signature-sentinel",
            "commit.signature=private-commit-signature-dot-sentinel",
            "commitSignature=private-commit-signature-camel-sentinel",
            "manifest_signature=private-manifest-signature-sentinel",
            "manifest.signature=private-manifest-signature-dot-sentinel",
            "manifestSignature=private-manifest-signature-camel-sentinel",
            "read_signature=private-read-signature-sentinel",
            "read.signature=private-read-signature-dot-sentinel",
            "readSignature=private-read-signature-camel-sentinel",
            "requestSignature=private-request-signature-camel-sentinel",
            "root_hash=private-root-hash-sentinel",
            "rootHash=private-root-hash-camel-sentinel",
            "old_root_hash=private-old-root-hash-sentinel",
            "oldRootHash=private-old-root-hash-camel-sentinel",
            "new_root_hash=private-new-root-hash-sentinel",
            "newRootHash=private-new-root-hash-camel-sentinel",
            "top_k=[private-topk-sentinel]",
            "topK=[private-topk-camel-sentinel]",
            "result_ids=[private-result-id-sentinel]",
            "result.ids=[private-result-id-dot-sentinel]",
            "resultIds=[private-result-id-camel-sentinel]",
            "point_token=private-point-token-sentinel",
            "point.token=private-point-token-dot-sentinel",
            "pointTokens=[private-point-token-camel-plural-sentinel]",
            "pointToken=private-point-token-camel-sentinel",
            "fetch_token=private-short-fetch-token-sentinel",
            "fetchTokens=[private-short-fetch-token-camel-sentinel]",
            "fetchToken=private-short-fetch-token-camel-singular-sentinel",
            "payload_fetch_token=private-fetch-token-singular-sentinel",
            "payload_fetch_tokens=[private-fetch-token-sentinel]",
            "payload.fetch.tokens=[private-fetch-token-dot-plural-sentinel]",
            "payloadFetchTokens=[private-fetch-token-camel-sentinel]",
            "payloadFetchToken=private-fetch-token-camel-singular-sentinel",
            "payload.fetch.token=private-fetch-token-dot-sentinel",
            "payload_bytes=private-payload-bytes-sentinel",
            "payloadBytes=private-payload-bytes-camel-sentinel",
            "payload_plaintext=private-payload-plaintext-sentinel",
            "payload.plaintext=private-payload-plaintext-dot-sentinel",
            "payloadPlaintext=private-payload-plaintext-camel-sentinel",
            "plaintext_payload=private-plaintext-payload-sentinel",
            "plaintextPayload=private-plaintext-payload-camel-sentinel",
            "payload_oram_leaf=private-payload-leaf-sentinel",
            "payloadOramLeaf=private-payload-leaf-camel-sentinel",
            "vector_bytes=private-vector-bytes-sentinel",
            "vectorBytes=private-vector-bytes-camel-sentinel",
            "vector_plaintext=private-vector-plaintext-sentinel",
            "vectorPlaintext=private-vector-plaintext-camel-sentinel",
            "plaintext_vector=private-plaintext-vector-sentinel",
            "plaintextVector=private-plaintext-vector-camel-sentinel",
            "position_map=private-position-map-sentinel",
            "positionMap=private-position-map-camel-sentinel",
            "positionMapBackup=private-position-map-backup-camel-sentinel",
            "positionMapBackups=[private-position-map-backups-camel-sentinel]",
            "position_map_snapshot=private-position-map-snapshot-sentinel",
            "position_map_snapshots=[private-position-map-snapshots-sentinel]",
            "positionMapSnapshot=private-position-map-snapshot-camel-sentinel",
            "position_maps=[private-position-map-plural-sentinel]",
            "positionMaps=[private-position-map-camel-plural-sentinel]",
            "oram_position_map=private-position-map-sentinel",
            "oramPositionMap=private-position-map-camel-sentinel",
            "oram_position_map_backup=private-oram-position-map-backup-sentinel",
            "oramPositionMapBackup=private-oram-position-map-backup-camel-sentinel",
            "oram_position_map_backups=[private-oram-position-map-backups-snake-sentinel]",
            "oramPositionMapBackups=[private-oram-position-map-backups-camel-sentinel]",
            "oram_position_maps=[private-oram-position-maps-snake-sentinel]",
            "oram_position_map_snapshot=private-oram-position-map-snapshot-snake-sentinel",
            "oram_position_map_snapshots=[private-oram-position-map-snapshots-snake-sentinel]",
            "oramPositionMapSnapshot=private-oram-position-map-snapshot-camel-sentinel",
            "tokenMap=private-token-map-sentinel",
            "tokenMapBackup=private-token-map-backup-sentinel",
            "token.map.backup=private-token-map-backup-dotted-sentinel",
            "token.map.backups=[private-token-map-backups-dotted-sentinel]",
            "token_map_backup=private-token-map-backup-snake-sentinel",
            "token_map_backups=[private-token-map-backups-snake-sentinel]",
            "tokenMapBackups=[private-token-map-backups-sentinel]",
            "token_maps=[private-token-maps-snake-sentinel]",
            "token.maps=[private-token-maps-dot-sentinel]",
            "token_map_snapshot=private-token-map-snapshot-snake-sentinel",
            "token.map.snapshot=private-token-map-snapshot-dot-sentinel",
            "token_map_snapshots=[private-token-map-snapshots-snake-sentinel]",
            "token.map.snapshots=[private-token-map-snapshots-dot-sentinel]",
            "tokenMapSnapshot=private-token-map-snapshot-sentinel",
            "tokenPositionMap=private-token-position-map-sentinel",
            "tokenPositionMapBackup=private-token-position-map-backup-sentinel",
            "token.position.map.backup=private-token-position-map-backup-dotted-sentinel",
            "token.position.map.backups=[private-token-position-map-backups-dotted-sentinel]",
            "token_position_map_backup=private-token-position-map-backup-snake-sentinel",
            "token_position_map_backups=[private-token-position-map-backups-snake-sentinel]",
            "tokenPositionMapBackups=[private-token-position-map-backups-sentinel]",
            "token_position_maps=[private-token-position-maps-snake-sentinel]",
            "token.position.maps=[private-token-position-maps-dot-sentinel]",
            "token_position_map_snapshot=private-token-position-map-snapshot-snake-sentinel",
            "token.position.map.snapshot=private-token-position-map-snapshot-dot-sentinel",
            "token_position_map_snapshots=[private-token-position-map-snapshots-snake-sentinel]",
            "token.position.map.snapshots=[private-token-position-map-snapshots-dot-sentinel]",
            "tokenPositionMapSnapshot=private-token-position-map-snapshot-sentinel",
            "client_state=private-client-state-sentinel",
            "clientState=private-client-state-camel-sentinel",
            "client_states=[private-client-states-snake-sentinel]",
            "clientStates=[private-client-states-camel-sentinel]",
            "client_state_backup=private-client-state-backup-sentinel",
            "clientStateBackup=private-client-state-backup-camel-sentinel",
            "clientStateBackups=[private-client-state-backups-camel-sentinel]",
            "client_state_backups=[private-client-state-backups-snake-sentinel]",
            "client_state_snapshot=private-client-state-snapshot-sentinel",
            "client.state.snapshot=private-client-state-snapshot-dotted-sentinel",
            "client.state.snapshot.json=private-client-state-snapshot-json-dotted-sentinel",
            "client_state_snapshots=[private-client-state-snapshots-sentinel]",
            "clientStateSnapshot=private-client-state-snapshot-camel-sentinel",
            "clientStateSnapshots=[private-client-state-snapshots-camel-sentinel]",
            "encrypted_client_state=private-encrypted-client-state-sentinel",
            "encrypted.client.state=private-encrypted-client-state-dotted-sentinel",
            "encrypted.client.state.json=private-encrypted-client-state-json-dotted-sentinel",
            "encrypted_client_state.json=private-encrypted-client-state-json-sentinel",
            "encryptedClientState=private-encrypted-client-state-camel-sentinel",
            "encrypted_client_state_backup=private-encrypted-client-state-backup-sentinel",
            "encryptedClientStateBackup=private-encrypted-client-state-backup-camel-sentinel",
            "encryptedClientStateBackups=[private-encrypted-client-state-backups-camel-sentinel]",
            "encrypted_client_state_backups=[private-encrypted-client-state-backups-snake-sentinel]",
            "encrypted_client_state_snapshot=private-encrypted-client-state-snapshot-sentinel",
            "encrypted.client.state.snapshot=private-encrypted-client-state-snapshot-dotted-sentinel",
            "encrypted.client.state.snapshot.json=private-encrypted-client-state-snapshot-json-dotted-sentinel",
            "encrypted_client_state_snapshot.bin=private-encrypted-client-state-snapshot-bin-sentinel",
            "encrypted_client_state_snapshot.json=private-encrypted-client-state-snapshot-json-sentinel",
            "encrypted_client_state_snapshots=[private-encrypted-client-state-snapshots-sentinel]",
            "encrypted_client_state_snapshots.json=[private-encrypted-client-state-snapshots-json-sentinel]",
            "encrypted.client.state.snapshots.json=[private-encrypted-client-state-snapshots-json-sentinel]",
            "encryptedClientStateSnapshot=private-encrypted-client-state-snapshot-camel-sentinel",
            "encryptedClientStateSnapshots=[private-encrypted-client-state-snapshots-camel-sentinel]",
            "client_state_ciphertext=private-client-state-ciphertext-sentinel",
            "client_state_ciphertexts=[private-client-state-ciphertexts-sentinel]",
            "clientStateCiphertext=private-client-state-ciphertext-camel-sentinel",
            "client_state_ciphertext_hash=private-client-state-ciphertext-hash-sentinel",
            "client_state_ciphertext_hash.bin=private-client-state-ciphertext-hash-bin-sentinel",
            "client_state_ciphertext_hash.json=private-client-state-ciphertext-hash-json-sentinel",
            "client_state_ciphertext_sha256=private-client-state-ciphertext-sha256-sentinel",
            "client_state_ciphertexts_sha256=[private-client-state-ciphertexts-sha256-sentinel]",
            "client_state_ciphertexts_sha256.bin=[private-client-state-ciphertexts-sha256-bin-sentinel]",
            "client_state_ciphertexts_sha256.json=[private-client-state-ciphertexts-sha256-json-sentinel]",
            "clientStateCiphertextHash=private-client-state-ciphertext-hash-camel-sentinel",
            "client_state_ciphertext_hashes=[private-client-state-ciphertext-hashes-snake-sentinel]",
            "client_state_ciphertext_hashes.bin=[private-client-state-ciphertext-hashes-bin-sentinel]",
            "client_state_ciphertext_hashes.json=[private-client-state-ciphertext-hashes-json-sentinel]",
            "clientStateCiphertextHashes=[private-client-state-ciphertext-hashes-camel-sentinel]",
            "clientStateCiphertextSha256=private-client-state-ciphertext-sha256-camel-sentinel",
            "clientStateCiphertextsSha256=[private-client-state-ciphertexts-sha256-camel-sentinel]",
            "encrypted_client_state_ciphertext=private-encrypted-client-state-ciphertext-sentinel",
            "encrypted_client_state_ciphertexts=[private-encrypted-client-state-ciphertexts-sentinel]",
            "encrypted_client_state_ciphertext_hash=private-encrypted-client-state-ciphertext-hash-sentinel",
            "encrypted_client_state_ciphertext_hash.bin=private-encrypted-client-state-ciphertext-hash-bin-sentinel",
            "encrypted_client_state_ciphertext_hash.json=private-encrypted-client-state-ciphertext-hash-json-sentinel",
            "encrypted_client_state_ciphertext_sha256=private-encrypted-client-state-ciphertext-sha256-sentinel",
            "encrypted_client_state_ciphertexts_sha256=[private-encrypted-client-state-ciphertexts-sha256-sentinel]",
            "encrypted_client_state_ciphertexts_sha256.bin=[private-encrypted-client-state-ciphertexts-sha256-bin-sentinel]",
            "encrypted_client_state_ciphertexts_sha256.json=[private-encrypted-client-state-ciphertexts-sha256-json-sentinel]",
            "encrypted_client_state_ciphertext_hashes=[private-encrypted-client-state-ciphertext-hashes-sentinel]",
            "encrypted_client_state_ciphertext_hashes.bin=[private-encrypted-client-state-ciphertext-hashes-bin-sentinel]",
            "encrypted_client_state_ciphertext_hashes.json=[private-encrypted-client-state-ciphertext-hashes-json-sentinel]",
            "encryptedClientStateCiphertext=private-encrypted-client-state-ciphertext-camel-sentinel",
            "encryptedClientStateCiphertextHash=private-encrypted-client-state-ciphertext-hash-camel-sentinel",
            "encryptedClientStateCiphertextHashes=[private-encrypted-client-state-ciphertext-hashes-camel-sentinel]",
            "encryptedClientStateCiphertextSha256=private-encrypted-client-state-ciphertext-sha256-camel-sentinel",
            "encryptedClientStateCiphertextsSha256=[private-encrypted-client-state-ciphertexts-sha256-camel-sentinel]",
            "state_ciphertext=private-state-ciphertext-sentinel",
            "state_ciphertexts=[private-state-ciphertexts-sentinel]",
            "state_ciphertext_sha256=private-state-ciphertext-sha256-sentinel",
            "state_ciphertexts_sha256=[private-state-ciphertexts-sha256-sentinel]",
            "state_ciphertexts_sha256.bin=[private-state-ciphertexts-sha256-bin-sentinel]",
            "state_ciphertexts_sha256.json=[private-state-ciphertexts-sha256-json-sentinel]",
            "stateCiphertext=private-state-ciphertext-camel-sentinel",
            "state_ciphertext_hash=private-state-ciphertext-hash-sentinel",
            "state_ciphertext_hash.bin=private-state-ciphertext-hash-bin-sentinel",
            "state_ciphertext_hash.json=private-state-ciphertext-hash-json-sentinel",
            "stateCiphertextHash=private-state-ciphertext-hash-camel-sentinel",
            "state_ciphertext_hashes=[private-state-ciphertext-hashes-sentinel]",
            "state_ciphertext_hashes.bin=[private-state-ciphertext-hashes-bin-sentinel]",
            "state_ciphertext_hashes.json=[private-state-ciphertext-hashes-json-sentinel]",
            "stateCiphertextHashes=[private-state-ciphertext-hashes-camel-sentinel]",
            "stateCiphertextSha256=private-state-ciphertext-sha256-camel-sentinel",
            "stateCiphertextsSha256=[private-state-ciphertexts-sha256-camel-sentinel]",
            "stash=private-stash-sentinel",
            "stashBackup=private-stash-backup-sentinel",
            "stashBackup.json=private-stash-backup-json-sentinel",
            "stashBackups=[private-stash-backups-camel-sentinel]",
            "stashBackups.json=[private-stash-backups-json-sentinel]",
            "stashSnapshot=private-stash-snapshot-sentinel",
            "stash_snapshots=[private-stash-snapshots-snake-sentinel]",
            "updated_bucket=private-updated-bucket-singular-sentinel",
            "updatedBucket=private-updated-bucket-camel-singular-sentinel",
            "updated_bucket_id=private-updated-bucket-id-sentinel",
            "updatedBucketId=private-updated-bucket-id-camel-sentinel",
            "updated_bucket_commitment=private-updated-bucket-commitment-sentinel",
            "updated.bucket.commitment=private-updated-bucket-commitment-dot-sentinel",
            "updatedBucketCommitment=private-updated-bucket-commitment-camel-sentinel",
            "updated_bucket_commitments=[private-updated-bucket-commitments-sentinel]",
            "updated.bucket.commitments=[private-updated-bucket-commitments-dot-sentinel]",
            "updatedBucketCommitments=[private-updated-bucket-commitments-camel-sentinel]",
            "updated_buckets=[private-updated-bucket-snake-sentinel]",
            "updatedBuckets=[private-updated-bucket-sentinel]",
            "unknown_field=private-unknown-field-sentinel",
            "unknownField=private-unknown-field-camel-sentinel",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-6", Some(secret));

            assert!(payload.contains("crypto material omitted"), "{payload}");
            assert!(!payload.contains("sentinel"), "{payload}");
        }
    }

    #[test]
    fn test_build_report_payload_redacts_private_oram_signing_key_identifiers() {
        for secret in [
            "owner_signing_key_id=private-owner-signing-key-id-sentinel",
            "ownerSigningKeyId=private-owner-signing-key-id-camel-sentinel",
            "owner_signing_key_ids=[private-owner-signing-key-ids-sentinel]",
            "ownerSigningKeyIds=[private-owner-signing-key-ids-camel-sentinel]",
            "signing_key_id=private-signing-key-id-sentinel",
            "signingKeyId=private-signing-key-id-camel-sentinel",
            "signing_key_ids=[private-signing-key-ids-sentinel]",
            "signingKeyIds=[private-signing-key-ids-camel-sentinel]",
            "signature_public_keys={private-signing-key-registry-sentinel: public-key-sentinel}",
            "signaturePublicKeys={private-signing-key-registry-camel-sentinel: public-key-sentinel}",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-7", Some(secret));

            assert!(payload.contains("crypto material omitted"), "{payload}");
            assert!(!payload.contains("sentinel"), "{payload}");
        }
    }

    #[test]
    fn test_build_report_payload_preserves_non_secret_context() {
        let payload = ErrorReporter::build_report_payload(
            "ordinary panic in optimizer worker",
            "node-5",
            Some("frame: src/common/query.rs:123"),
        );

        assert!(payload.contains("ordinary panic in optimizer worker"));
        assert!(payload.contains("src/common/query.rs:123"));
        assert!(!payload.contains("crypto material omitted"));
    }
}
