use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use dashmap::{DashMap, DashSet};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Error, Server},
    Code::{self},
    Response, Status,
};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

pub mod mesh {
    pub mod service_connector {
        tonic::include_proto!("mesh.service_connector");

        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("mesh.service_connector");
    }
}

use crate::mesh::service_connector::{
    BootstrapSnapshot, ClientMessage, PeerAnnouncement, ServerMessage, SignalEnvelope,
};
use common::tracing::init_tracing;
use mesh::service_connector::mesh_network_service_server::{
    MeshNetworkService, MeshNetworkServiceServer,
};

type ResponseStream = std::pin::Pin<
    Box<dyn tokio_stream::Stream<Item = std::result::Result<ServerMessage, Status>> + Send>,
>;

pub struct ClusterState {
    connected_nodes: DashSet<Uuid>,
    connected_nodes_channels: DashMap<Uuid, broadcast::Sender<SignalEnvelope>>,
    registration_events: broadcast::Sender<Uuid>,
}

pub struct AppState {
    state: Arc<ClusterState>,
}

#[tonic::async_trait]
impl MeshNetworkService for AppState {
    type ConnectNodeStream = ResponseStream;

    async fn connect_node(
        &self,
        request: tonic::Request<tonic::Streaming<ClientMessage>>,
    ) -> Result<tonic::Response<Self::ConnectNodeStream>, tonic::Status> {
        let mut inbound_stream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let self_clone = Arc::clone(&self.state);

        let (node_id, initial_payload) = match inbound_stream.message().await {
            Ok(Some(first_msg)) => {
                if first_msg.from_node_id.is_empty()
                    || first_msg.payload.is_none()
                    || Uuid::parse_str(first_msg.from_node_id.as_str()).is_err()
                {
                    warn!("client attempted to connect with a malformed packet");
                    return Err(Status::new(
                        Code::InvalidArgument,
                        "Missing from_node_id or valid payload in initial request",
                    ));
                }

                info!(
                    "initial validation passed for node: {}",
                    first_msg.from_node_id
                );

                let node_id = Uuid::parse_str(first_msg.from_node_id.as_str())
                    .map_err(|_| Status::new(Code::Aborted, "failed to parse uuid"))?;

                (node_id, first_msg.payload)
            }
            Ok(None) => {
                return Err(Status::new(
                    Code::Aborted,
                    "Client closed stream immediately",
                ));
            }
            Err(e) => return Err(e),
        };

        if let Some(mesh::service_connector::client_message::Payload::Register(reg)) =
            initial_payload
        {
            println!(
                "Node wants to register on first message. Reconnect: {}",
                reg.is_reconnect
            );

            let welcome = ServerMessage {
                payload: Some(mesh::service_connector::server_message::Payload::Snapshot(
                    BootstrapSnapshot {
                        active_node_ids: self_clone
                            .connected_nodes
                            .iter()
                            .map(|x| x.to_string())
                            .collect(),
                    },
                )),
            };

            let _ = tx.send(Ok(welcome)).await;
            self_clone.connected_nodes.insert(node_id);
            let _ = self_clone
                .registration_events
                .send(node_id)
                .map_err(|_| Status::new(Code::Internal, "Couldnt Send Node Alert Out"));

            // INFO: Signalling
            {
                let channel_rx = if !self_clone.connected_nodes_channels.contains_key(&node_id) {
                    let (tx, channel_rx) = broadcast::channel::<SignalEnvelope>(32);
                    self_clone.connected_nodes_channels.insert(node_id, tx);
                    channel_rx
                } else {
                    let tx = self_clone.connected_nodes_channels.get(&node_id).unwrap();
                    tx.subscribe()
                };

                let broadcast_tx = tx.clone();
                tokio::spawn(async move {
                    let mut channel_rx = channel_rx;

                    loop {
                        tokio::select! {
                            broadcast_msg = channel_rx.recv() => {
                                match broadcast_msg {
                                    Ok(payload) => {
                                        let server_msg = ServerMessage {
                                            payload: Some(mesh::service_connector::server_message::Payload::Signal(
                                                SignalEnvelope {
                                                    source_node_id: payload.source_node_id,
                                                    raw_json: payload.raw_json,
                                                    target_node_id: payload.target_node_id,
                                                }
                                            )),
                                        };

                                        if broadcast_tx.send(Ok(server_msg)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                        warn!("Node {} lagged behind by {} broadcast messages", node_id, skipped);
                                        continue;
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        // INFO: Registration Events
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
        let mut kill_switch = Some(kill_tx);

        let mut global_rx = self_clone.registration_events.subscribe();
        let broadcast_tx = tx.clone();

        tokio::spawn(async move {
            let mut kill_rx = kill_rx;

            loop {
                tokio::select! {
                    global_msg = global_rx.recv() => {
                        if let Ok(new_node_uuid) = global_msg {
                            if new_node_uuid == node_id { continue; }

                            let discovery_msg = ServerMessage {
                                payload: Some(mesh::service_connector::server_message::Payload::Announcement(
                                    PeerAnnouncement {
                                            joined_node_id: new_node_uuid.to_string(),
                                    }
                                )),
                            };
                            if broadcast_tx.send(Ok(discovery_msg)).await.is_err() { break; }
                        }
                    }

                    _ = &mut kill_rx => {
                        info!("Node {} finished initial setup. no new alerts will be recieved", node_id);
                        break;
                    }
                }
            }
        });

        // INFO: main message router
        tokio::spawn(async move {
            while let Ok(Some(client_msg)) = inbound_stream.message().await {
                if client_msg.from_node_id.is_empty() || client_msg.payload.is_none() {
                    let stream_err = Err(Status::new(
                        Code::InvalidArgument,
                        "Mid-stream message missing node ID or payload",
                    ));

                    let _ = tx.send(stream_err).await;
                    break;
                }

                if let Some(payload) = client_msg.payload {
                    match payload {
                        mesh::service_connector::client_message::Payload::Register(_) => {
                            // INFO: dont ack the request as registration already happened on first
                            // message
                            continue;
                        }
                        mesh::service_connector::client_message::Payload::RegisterCompletion(
                            status,
                        ) => {
                            if status {
                                info!("Received registration completion from node {}", node_id);

                                if let Some(sender) = kill_switch.take() {
                                    let _ = sender.send(());
                                }
                            }
                        }
                        mesh::service_connector::client_message::Payload::Signal(sig) => {
                            debug!(
                                "Sending Signalling info from {0} to {1}",
                                sig.source_node_id, sig.target_node_id
                            );
                            let target_node_uuid =
                                match Uuid::parse_str(sig.target_node_id.as_str()) {
                                    Ok(uuid) => uuid,
                                    Err(_) => {
                                        break;
                                    }
                                };

                            let channel_tx = self_clone
                                .connected_nodes_channels
                                .get(&target_node_uuid)
                                .map(|r| r.value().clone());

                            if let Some(tx) = channel_tx {
                                let _ = tx.send(sig);
                            }
                        }
                    }
                }
            }

            info!(
                "Client disconnected. da loop ended, tx is now dropping, stream is safely closing."
            );

            self_clone.connected_nodes.remove(&node_id);
            self_clone.connected_nodes_channels.remove(&node_id);
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::ConnectNodeStream
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _guard = init_tracing();

    let host_on: SocketAddr = "[::]:3006".parse().unwrap();

    let nodes = DashSet::new();
    let established_nodes_channel = DashMap::new();
    let registration_bus = broadcast::Sender::new(1024);

    let cluster_state = Arc::new(ClusterState {
        connected_nodes: nodes,
        connected_nodes_channels: established_nodes_channel,
        registration_events: registration_bus,
    });

    let app_state = AppState {
        state: cluster_state,
    };

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(mesh::service_connector::FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    let service_connector_service = MeshNetworkServiceServer::new(app_state);

    info!("Listening on {0}:{1}", host_on.ip(), host_on.port());
    Server::builder()
        .add_service(reflection_service)
        .add_service(service_connector_service)
        .serve(host_on)
        .await
}
