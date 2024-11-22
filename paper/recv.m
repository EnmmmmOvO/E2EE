let root_key = {
    let mut key_material = Vec::new();

    let dh1 = x25519(ik_private, spk);
    key_material.extend_from_slice(&dh1);

    let dh2 = x25519(ek.private, ikp);
    key_material.extend_from_slice(&dh2);

    let dh3 = x25519(ek.private, spk);
    key_material.extend_from_slice(&dh3);

    let dh4 = x25519(ek.private, opk);
    key_material.extend_from_slice(&dh4);

    let hk = Hkdf::<Sha256>::new(None, &key_material);
    let mut root_key = [0u8; 32];
    hk.expand(b"X3DH-Root-Key", &mut root_key)
        .map_err(|e| format!("Failed to expand key: {}", e))?;

    Ok::<[u8; 32], Box<dyn Error>>(root_key)
}?;