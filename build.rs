// Build script to generate Rust code from protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["proto/message_gateway.proto"],
            &["proto"],
        )?;
    Ok(())
}
