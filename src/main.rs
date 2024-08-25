use anyhow::Result;
use boringtun::{noise, x25519};
use rand::{rngs::OsRng, RngCore as _};

fn main() -> Result<()> {
    // Create two endpoints
    let (mut my_tun, mut their_tun) = {
        let my_secret_key = x25519::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = noise::Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None)
            .map_err(|e| anyhow::anyhow!("error creating noise::Tunn {e:?}"))?;
        let their_tun =
            noise::Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None)
                .map_err(|e| anyhow::anyhow!("error creating noise::Tunn {e:?}"))?;
        (my_tun, their_tun)
    };

    // Create a handshake initiation packet
    let mut dst = vec![0u8; 2048];
    let handshake_init = my_tun.format_handshake_initiation(&mut dst, false);
    assert!(matches!(
        handshake_init,
        noise::TunnResult::WriteToNetwork(_)
    ));
    let handshake_init = if let noise::TunnResult::WriteToNetwork(sent) = handshake_init {
        sent
    } else {
        unreachable!();
    };

    let handshake_data = handshake_init;

    println!(
        "handshake_data: len={}: {:?}",
        handshake_data.len(),
        handshake_data
    );

    // Give that handshake request to the other endpoint, and get a response
    let mut handshake_response = [0u8; 2048];
    let res = their_tun.decapsulate(None, &handshake_data, &mut handshake_response);
    assert!(matches!(res, noise::TunnResult::WriteToNetwork(_)));

    let handshake_resp = if let noise::TunnResult::WriteToNetwork(sent) = res {
        sent
    } else {
        unreachable!();
    };

    println!(
        "handshake_resp: len={}: {:?}",
        handshake_resp.len(),
        handshake_resp
    );

    // Give that response back to the original endpoint
    let mut dst = vec![0u8; 2048];
    let keepalive = my_tun.decapsulate(None, handshake_resp, &mut dst);
    assert!(matches!(keepalive, noise::TunnResult::WriteToNetwork(_)));

    let keepalive = if let noise::TunnResult::WriteToNetwork(sent) = keepalive {
        sent
    } else {
        unreachable!();
    };

    println!("keepalive: len={}: {:?}", keepalive.len(), keepalive);

    // Parse the keep alive packet
    let mut dst = vec![0u8; 2048];
    let keepalive = their_tun.decapsulate(None, keepalive, &mut dst);
    assert!(matches!(keepalive, noise::TunnResult::Done));

    for datasize in [1, 2, 4, 8, 16] {
        // Transfer data from my to their
        let mut data = Vec::new();
        for i in 0u8..datasize {
            data.push(i);
        }
        let mut dst = vec![0u8; 2048];
        let res = my_tun.encapsulate(&data, &mut dst);
        assert!(matches!(res, noise::TunnResult::WriteToNetwork(_)));
        let encrypted_data = if let noise::TunnResult::WriteToNetwork(sent) = res {
            sent
        } else {
            unreachable!();
        };
        assert_ne!(data, encrypted_data);
        assert_ne!(data.len(), encrypted_data.len());

        println!("data: len={}: {:?}", data.len(), data);
        println!(
            "encrypted_data: len={}: {:?}",
            encrypted_data.len(),
            encrypted_data
        );

        let packet = noise::Tunn::parse_incoming_packet(&encrypted_data)
            .map_err(|e| anyhow::anyhow!("Could not parse incoming packet: {e:?}"))?;
        let packet = if let noise::Packet::PacketData(data) = packet {
            data
        } else {
            anyhow::bail!("Expected data packet");
        };

        println!("  packet: {packet:?}");
        println!(
            "  encrypted_encapsulated_packet len: {}",
            packet.encrypted_encapsulated_packet.len()
        );
    }

    Ok(())
}
