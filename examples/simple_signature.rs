use bls_crypto::{
    hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1, PrivateKey, PublicKey, Signature,
};

use ark_serialize::CanonicalSerialize;

use ark_std::test_rng;
use clap::{Arg, Command};

fn main() {
    let matches = Command::new("SimpleAggregatedSignature")
        .about("Show an example of a simple signature with a random key")
        .arg(
            Arg::new("message")
                .short('m')
                .value_name("MESSAGE")
                .help("Sets the message to sign")
                .required(true),
        )
        .get_matches();

    let message = matches.get_one::<String>("message").unwrap();

    println!("matches: {}", message);

    let rng = &mut test_rng();

    println!("rng");

    let try_and_increment = &*COMPOSITE_HASH_TO_G1;

    let sk1 = PrivateKey::generate(rng);
    let mut sk1_bytes = vec![];
    sk1.serialize_compressed(&mut sk1_bytes).unwrap();
    println!("sk1: {}", hex::encode(sk1_bytes));

    let sk2 = PrivateKey::generate(rng);
    let mut sk2_bytes = vec![];
    sk2.serialize_compressed(&mut sk2_bytes).unwrap();
    println!("sk2: {}", hex::encode(sk2_bytes));

    let sk3 = PrivateKey::generate(rng);
    let mut sk3_bytes = vec![];
    sk3.serialize_compressed(&mut sk3_bytes).unwrap();
    println!("sk3: {}", hex::encode(sk3_bytes));

    println!("Starting!\n\n");

    let sig1 = sk1
        .sign(&message.as_bytes(), &[], try_and_increment)
        .unwrap();
    let mut sig1_bytes = vec![];
    sig1.serialize_compressed(&mut sig1_bytes).unwrap();
    println!("sig1: {}", hex::encode(sig1_bytes));

    let sig2 = sk2
        .sign(&message.as_bytes(), &[], try_and_increment)
        .unwrap();
    let mut sig2_bytes = vec![];
    sig2.serialize_compressed(&mut sig2_bytes).unwrap();
    println!("sig2: {}", hex::encode(sig2_bytes));

    let sig3 = sk3
        .sign(&message.as_bytes(), &[], try_and_increment)
        .unwrap();
    let mut sig3_bytes = vec![];
    sig3.serialize_compressed(&mut sig3_bytes).unwrap();
    println!("sig3: {}", hex::encode(sig3_bytes));

    let apk = PublicKey::aggregate(&[
        sk1.to_public(),
        sk2.to_public(),
        sk3.to_public(),
        sk3.to_public(),
    ]);
    let mut apk_bytes = vec![];
    apk.serialize_compressed(&mut apk_bytes).unwrap();
    println!("apk: {}", hex::encode(apk_bytes));
    let asig1 = Signature::aggregate(&[sig1, sig3.clone()]);
    let asig2 = Signature::aggregate(&[sig2, sig3]);
    let asig = Signature::aggregate(&[asig1, asig2]);
    let mut asig_bytes = vec![];
    asig.serialize_compressed(&mut asig_bytes).unwrap();
    println!("asig: {}", hex::encode(asig_bytes));
    apk.verify(&message.as_bytes(), &[], &asig, try_and_increment)
        .unwrap();
    println!("aggregated signature verified successfully");
}
