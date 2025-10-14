use std::{
    env,
    error::Error,
    ffi::OsString,
    io::{self, Read},
};

use gsv_soldering_core::{host, types};

#[derive(serde::Serialize, serde::Deserialize)]
struct CliWiresInput {
    instances_wires: Vec<Vec<(u128, u128)>>,
    nonce: u128,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CliSolderedLabelsData {
    deltas: Vec<Vec<(u128, u128)>>,
    base_commitment: Vec<([u8; 32], [u8; 32])>,
    base_nonce_commitment: Vec<([u8; 32], [u8; 32])>,
    commitments: Vec<Vec<([u8; 32], [u8; 32])>>,
    nonce: u128,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(cmd) if cmd == OsString::from("prove") => prove(),
        Some(cmd) if cmd == OsString::from("verify") => verify(),
        _ => {
            eprintln!("usage: gsv-soldering-cli [prove|verify]\n  expect hex-encoded bincode payload on stdin");
            Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid command").into())
        }
    }
}

fn prove() -> Result<(), Box<dyn Error>> {
    let input: CliWiresInput = read_payload()?;
    let proof = host::prove(&types::WiresInput {
        instances_wires: input.instances_wires,
        nonce: input.nonce,
    });
    write_payload(&proof)
}

fn verify() -> Result<(), Box<dyn Error>> {
    let proof: host::ProvenSolderedLabelsData = read_payload()?;
    let labels = host::verify(proof);
    let response = CliSolderedLabelsData {
        deltas: labels.deltas,
        base_commitment: labels.base_commitment,
        base_nonce_commitment: labels.base_nonce_commitment,
        commitments: labels.commitments,
        nonce: labels.nonce,
    };
    write_payload(&response)
}

fn read_payload<T>() -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let mut stdin = String::new();
    io::stdin().read_to_string(&mut stdin)?;
    let payload = stdin.split_whitespace().collect::<String>();
    let bytes = hex::decode(payload.trim())?;
    let value = bincode::deserialize(&bytes)?;
    Ok(value)
}

fn write_payload<T>(value: &T) -> Result<(), Box<dyn Error>>
where
    T: serde::Serialize,
{
    let bytes = bincode::serialize(value)?;
    let output = hex::encode(bytes);
    println!("{output}");
    Ok(())
}
