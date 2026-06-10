use anyhow::Error;

fn main() -> Result<(), Error> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "protos/mesh_network.proto",
                "protos/auth_backend.proto",
                "protos/gradegetter.proto",
                "protos/gradegetter_backend.proto",
                "protos/notification_backend.proto",
                "protos/nanopass_backend.proto",
                "protos/smalltalk_backend.proto",
                "protos/service_connector.proto",
            ],
            &["protos"],
        )?;
    Ok(())
}
