use std::{env::current_dir, net::SocketAddr};

use axum::{routing::post, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use k8s_openapi::api::core::v1::Pod;
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
    DynamicObject, ResourceExt,
};
use tracing::{debug, error, info, trace, warn};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new().route("/mutate", post(mutate_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let listener = std::net::TcpListener::bind(addr).unwrap();

    if std::env::var("TLS_ENABLED").is_ok_and(|var| var == "true") {
        let current_dir = current_dir().unwrap();
        debug!("current dir: {:?}", current_dir);
        let cert_file = current_dir
            .clone()
            .join(std::env::var("CERT_PEM").expect("CERT_PEM is not set"));
        debug!("loading cert from {:?}", cert_file);

        let private_key_file = current_dir
            .clone()
            .join(std::env::var("KEY_PEM").expect("KEY_PEM is not set"));
        debug!("loading private key from {:?}", private_key_file);

        // configure certificate and private key used by https
        let config = RustlsConfig::from_pem_file(cert_file, private_key_file)
            .await
            .unwrap();

        tracing::info!("starting with TLS");
        axum_server::from_tcp_rustls(listener, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        tracing::info!("starting without TLS");
        axum_server::from_tcp(listener)
            .serve(app.into_make_service())
            .await
            .unwrap();
    };
}

async fn mutate_handler(
    Json(payload): Json<AdmissionReview<Pod>>,
) -> Json<AdmissionReview<DynamicObject>> {
    tracing::trace!(?payload, "hit server with valid request");
    let req: AdmissionRequest<Pod> = match payload.try_into() {
        Ok(req) => req,
        Err(err) => {
            error!("invalid request: {}", err.to_string());
            return Json(AdmissionResponse::invalid(err.to_string()).into_review());
        }
    };
    trace!(?req, "parsed request");

    let mut res = AdmissionResponse::from(&req);

    if let Some(pod) = req.object {
        let name = pod.name_any();
        res = match mutate_pod(res.clone(), &pod) {
            Ok(res) => {
                info!("accepted: {:?} on Pod {}", req.operation, name);
                res
            }
            Err(err) => {
                warn!("denied: {:?} on {} ({})", req.operation, name, err);
                res.deny(err.to_string())
            }
        };
    };
    debug!(?res, "returning response");
    Json(res.into_review())
}

// The main handler and core business logic, failures here implies rejected applies
fn mutate_pod(res: AdmissionResponse, pod: &Pod) -> anyhow::Result<AdmissionResponse> {
    if let Some(pod_spec) = &pod.spec {
        let mut patches = Vec::new();
        if let Some(init_containers) = &pod_spec.init_containers {
            for (i, init_container) in init_containers.iter().enumerate() {
                if init_container
                    .image_pull_policy
                    .as_ref()
                    .is_some_and(|policy| policy == "Always")
                {
                    patches.push(json_patch::PatchOperation::Replace(
                        json_patch::ReplaceOperation {
                            path: format!("/spec/initContainers/{}/imagePullPolicy", i),
                            value: "IfNotPresent".into(),
                        },
                    ))
                }
            }
        }
        for (i, container) in pod_spec.containers.iter().enumerate() {
            if container
                .image_pull_policy
                .as_ref()
                .is_some_and(|policy| policy == "Always")
            {
                patches.push(json_patch::PatchOperation::Replace(
                    json_patch::ReplaceOperation {
                        path: format!("/spec/containers/{}/imagePullPolicy", i),
                        value: "IfNotPresent".into(),
                    },
                ))
            }
        }
        if !patches.is_empty() {
            debug!(len=%patches.len(), "applying patches");
            return Ok(res.with_patch(json_patch::Patch(patches))?);
        }
    }
    Ok(res)
}
