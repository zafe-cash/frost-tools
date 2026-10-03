//! Tests for running DKG with `frost-client` through `frostd`.

use std::{error::Error, rc::Rc, time::Duration};

use frost_client::{
    api::{self, PublicKey},
    cipher::{Cipher, PrivateKey},
    client::Client,
    dkg::{args::ProcessedArgs, cli::cli_for_processed_args, comms::http::DKGParams},
};
use frost_ed25519::Ed25519Sha512;
use frostd::args::Args;
use rand::thread_rng;

const PORT: u16 = 2745;

/// A participant in the tests: its communication key pair.
struct User {
    privkey: PrivateKey,
    pubkey: PublicKey,
}

impl User {
    fn new() -> Self {
        let (privkey, pubkey) = Cipher::generate_keypair().unwrap();
        Self { privkey, pubkey }
    }
}

/// Return the DKG arguments for `user`, who knows the given `contacts`.
/// `participants` must be specified only for the user who creates the session.
fn dkg_args(
    user: &User,
    contacts: &[&User],
    participants: &[&User],
    threshold: Option<u16>,
    description: Option<&str>,
) -> ProcessedArgs<Ed25519Sha512> {
    let contacts: Vec<PublicKey> = contacts.iter().map(|u| u.pubkey.clone()).collect();
    ProcessedArgs {
        cli: false,
        http: true,
        ip: "localhost".to_string(),
        port: PORT,
        comm_privkey: Some(user.privkey.clone()),
        comm_pubkey: Some(user.pubkey.clone()),
        comm_participant_pubkey_getter: Some(Rc::new(move |pubkey| {
            contacts.contains(pubkey).then(|| pubkey.clone())
        })),
        min_signers: threshold,
        description: description.map(str::to_string),
        max_signers: None,
        participants: participants.iter().map(|u| u.pubkey.clone()).collect(),
        identifier: None,
    }
}

/// Run the DKG for the given arguments, returning the threshold, the group
/// public key and the description.
async fn run_dkg(
    args: ProcessedArgs<Ed25519Sha512>,
) -> Result<(u16, Vec<u8>, Option<String>), Box<dyn Error>> {
    let mut input = "".as_bytes();
    let mut output = Vec::new();
    let (key_package, public_key_package, _, description) =
        cli_for_processed_args(args, &mut input, &mut output).await?;
    Ok((
        *key_package.min_signers(),
        public_key_package.verifying_key().serialize()?,
        description,
    ))
}

/// Return a client logged in as `user`.
async fn login(user: &User) -> Result<Client, Box<dyn Error>> {
    let mut client = Client::new(format!("https://localhost:{PORT}"));
    let challenge = client.challenge().await?.challenge;
    let signature = user.privkey.sign(challenge.as_bytes(), thread_rng())?;
    client
        .login(&api::LoginArgs {
            challenge,
            pubkey: user.pubkey.clone(),
            signature: signature.to_vec(),
        })
        .await?;
    Ok(client)
}

/// Wait until `user` is in a session, so that they can join it.
async fn wait_for_session(user: &User) -> Result<(), Box<dyn Error>> {
    let client = login(user).await?;
    while client.list_sessions().await?.session_ids.is_empty() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Create a DKG session as `creator` (as a buggy or malicious client would),
/// send `params` to `joiner`, and return the error `joiner` gets.
async fn joiner_error_for_params(params: DKGParams) -> Result<String, Box<dyn Error>> {
    let (creator, joiner, other) = (User::new(), User::new(), User::new());
    let all = [&creator, &joiner, &other];

    let client = login(&creator).await?;
    let session_id = client
        .create_new_session(&api::CreateNewSessionArgs {
            pubkeys: all.iter().map(|u| u.pubkey.clone()).collect(),
            message_count: 1,
        })
        .await?
        .session_id;
    let mut cipher = Cipher::new(
        creator.privkey.clone(),
        vec![joiner.pubkey.clone(), other.pubkey.clone()],
    )?;
    client
        .send(&api::SendArgs {
            session_id,
            recipients: vec![joiner.pubkey.clone()],
            msg: cipher.encrypt(Some(&joiner.pubkey), serde_json::to_vec(&params)?)?,
        })
        .await?;

    let err = run_dkg(dkg_args(&joiner, &all, &[], None, None))
        .await
        .expect_err("joiner must reject the parameters");
    Ok(err.to_string())
}

/// Spawn frostd with a self-signed certificate, which the clients will trust.
async fn spawn_server() -> Result<tempfile::TempDir, Box<dyn Error>> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;
    let temp_dir = tempfile::tempdir()?;
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("cert.key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;

    // frost-client uses the platform's root certificates, which can be
    // overridden with this variable. This test binary only runs the tests in
    // this file, so this does not affect other tests.
    std::env::set_var("SSL_CERT_FILE", &cert_path);

    let args = Args {
        ip: "127.0.0.1".to_string(),
        port: PORT,
        tls_cert: Some(cert_path.to_str().unwrap().to_string()),
        tls_key: Some(key_path.to_str().unwrap().to_string()),
        no_tls_very_insecure: false,
    };
    tokio::spawn(async move { frostd::run(&args).await.unwrap() });

    // Wait for server to start listening
    while tokio::net::TcpStream::connect(("127.0.0.1", PORT))
        .await
        .is_err()
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(temp_dir)
}

/// The scenarios run sequentially against a single server, since frostd can
/// only be started once per process.
#[tokio::test]
async fn test_dkg_params() -> Result<(), Box<dyn Error>> {
    let _temp_dir = spawn_server().await?;

    // Only the creator specifies the threshold and description; Bob also
    // specifies the threshold to check it, and Eve uses her own description.
    let (alice, bob, eve) = (User::new(), User::new(), User::new());
    let all = [&alice, &bob, &eve];
    let (a, b, e) = tokio::join!(
        run_dkg(dkg_args(&alice, &all, &all, Some(2), Some("Our group"))),
        async {
            wait_for_session(&bob).await?;
            run_dkg(dkg_args(&bob, &all, &[], Some(2), None)).await
        },
        async {
            wait_for_session(&eve).await?;
            run_dkg(dkg_args(&eve, &all, &[], None, Some("Eve's name"))).await
        },
    );
    let (a, b, e) = (a?, b?, e?);
    assert_eq!(a.0, 2);
    assert_eq!(a.0, b.0);
    assert_eq!(a.0, e.0);
    assert_eq!(a.1, b.1);
    assert_eq!(a.1, e.1);
    assert_eq!(a.2.as_deref(), Some("Our group"));
    assert_eq!(b.2.as_deref(), Some("Our group"));
    assert_eq!(e.2.as_deref(), Some("Eve's name"));

    // A joiner who specifies a different threshold aborts.
    let (alice, bob, eve) = (User::new(), User::new(), User::new());
    let all = [&alice, &bob, &eve];
    tokio::select! {
        r = run_dkg(dkg_args(&alice, &all, &all, Some(2), Some("Our group"))) => {
            panic!("creator must wait for the others: {:?}", r.map_err(|e| e.to_string()));
        }
        r = async {
            wait_for_session(&bob).await?;
            run_dkg(dkg_args(&bob, &all, &[], Some(3), None)).await
        } => {
            let err = r.expect_err("must fail").to_string();
            assert!(err.contains("does not match"), "{err}");
        }
    }

    // The creator can't choose an invalid threshold, and no session is created.
    let (alice, bob, eve) = (User::new(), User::new(), User::new());
    let all = [&alice, &bob, &eve];
    for threshold in [1, 4] {
        let err = run_dkg(dkg_args(&alice, &all, &all, Some(threshold), Some("x")))
            .await
            .expect_err("must fail")
            .to_string();
        assert!(err.contains("threshold must be at least 2"), "{err}");
    }
    assert!(login(&bob)
        .await?
        .list_sessions()
        .await?
        .session_ids
        .is_empty());

    // Joiners validate what the creator sends.
    let err = joiner_error_for_params(DKGParams {
        threshold: 4,
        description: None,
    })
    .await?;
    assert!(err.contains("invalid threshold"), "{err}");
    let err = joiner_error_for_params(DKGParams {
        threshold: 2,
        description: Some("\x1b[2J".to_string()),
    })
    .await?;
    assert!(err.contains("invalid description"), "{err}");

    Ok(())
}
