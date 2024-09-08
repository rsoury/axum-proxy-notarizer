// This example shows how to notarize Twitter DMs.
//
// The example uses the notary server implemented in ../../../notary/server

use axum::{response::Html, routing::get, Router};
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{self, Bytes},
    Method, Request, StatusCode,
};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::str;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

// Setting of the application server
const SERVER_DOMAIN: &str = "jsonplaceholder.typicode.com";

// Setting of the notary server — make sure these are the same with the config in ../../../notary/server
const NOTARY_HOST: &str = "127.0.0.1";
// const NOTARY_HOST: &str = "https://notary-au-1.verity.usher.so/";
const NOTARY_PORT: u16 = 7047;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new().route("/proxy", get(notarizer));

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn notarizer() -> String {
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder().max_sent_data(MAX_SENT_DATA)
    .max_recv_data(MAX_RECV_DATA).build().unwrap();

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    // Configure a new prover with the unique session id returned from notary client.
    let prover_config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    // Open a new socket to the application server.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the DMs
    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!("https://{SERVER_DOMAIN}/posts/98"))
        .method(Method::GET)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Cache-Control", "no-cache")
        .header("Connection", "close")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .body(Empty::<Bytes>::new())
        .unwrap();

    println!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    println!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    println!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    println!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // serde_json::to_string_pretty(&parsed).unwrap()

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http().unwrap().start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit().unwrap();

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    println!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("tweet_notarized_session.json")
        .await
        .unwrap();
    file.write_all(
        serde_json::to_string_pretty(notarized_session.session())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("tweet_proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    serde_json::to_string_pretty(&parsed).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::Router;
    use reqwest::Client; // Updated import
    use tokio::task;
    use tokio::sync::Semaphore;
    use std::sync::Arc; // Add this import

    #[tokio::test]
    async fn load_test_proxy_endpoint() {
        // Start the server in a background task
        let server_task = tokio::spawn(async {
            let app = Router::new().route("/proxy", get(notarizer));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8080") // Use a different port for tests
                .await
                .expect("Failed to bind to address");
            axum::serve(listener, app).await.expect("Failed to serve app");
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Number of requests to simulate
        let num_requests = 100;

        // Create a reqwest client
        let client = Client::new();

        // Create a semaphore to limit concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(4)); // Wrap semaphore in Arc

        // Spawn tasks to send requests concurrently
        let mut tasks = vec![];
        for i in 0..num_requests {
            let client = client.clone();
            let semaphore = semaphore.clone(); // Clone the Arc
            tasks.push(task::spawn(async move {
                let permit = semaphore.acquire_owned().await.unwrap(); // Acquire permit
                println!("Requesting : {}", i);
                let response = client
                    .get("http://127.0.0.1:8080/proxy")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let response_text = response.text().await.unwrap();
                println!("Request complete : {} : {}", i, response_text);
                drop(permit); // Release the permit
            }));
        }

        // Wait for all tasks to complete
        for task in tasks {
            task.await.unwrap();
        }

        // Stop the server
        server_task.abort();
    }
}
