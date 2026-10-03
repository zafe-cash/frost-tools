//! HTTP implementation of the Comms trait.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
    vec,
};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{
    keys::dkg::{round1, round2},
    Ciphersuite, Identifier,
};

use crate::cipher::Cipher;
use crate::client::Client;
use crate::{
    api::{self, Msg, PublicKey, Uuid},
    session::DKGSessionState,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use super::super::args::ProcessedArgs;
use super::Comms;

/// The DKG parameters which the participant who created the DKG session sends
/// to the other participants before Round 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGParams {
    /// The threshold (minimum number of signers).
    pub threshold: u16,
    /// The group description.
    pub description: Option<String>,
}

pub struct HTTPComms<C: Ciphersuite> {
    client: Client,
    session_id: Option<Uuid>,
    args: ProcessedArgs<C>,
    state: DKGSessionState<C>,
    identifier: Option<Identifier<C>>,
    pubkeys: HashMap<PublicKey, Identifier<C>>,
    /// The public key of the participant who created the DKG session.
    coordinator_pubkey: Option<PublicKey>,
    cipher: Option<Cipher>,
    /// Messages received from other participants while waiting for the DKG
    /// parameters, to be handled in Round 1.
    pending_msgs: Vec<Msg>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", args.ip, args.port)),
            session_id: None,
            args: args.clone(),
            state: DKGSessionState::default(),
            identifier: None,
            pubkeys: Default::default(),
            coordinator_pubkey: None,
            cipher: None,
            pending_msgs: Vec::new(),
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_identifier_and_max_signers(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        let comm_pubkey = self
            .args
            .comm_pubkey
            .clone()
            .ok_or_eyre("comm_pubkey must be specified")?;

        self.client
            .login(&api::LoginArgs {
                challenge,
                pubkey: comm_pubkey.clone(),
                signature: signature.to_vec(),
            })
            .await?;

        let session_id = if !self.args.participants.is_empty() {
            // Validate the threshold before creating the session, since the
            // other participants will use the one we send them.
            let min_signers = self
                .args
                .min_signers
                .ok_or_eyre("threshold must be specified when creating a DKG session")?;
            if min_signers < 2 || min_signers as usize > self.args.participants.len() {
                return Err(eyre!(
                    "threshold must be at least 2 and at most the number of participants ({})",
                    self.args.participants.len()
                )
                .into());
            }
            eprintln!("Creating DKG session...");
            let r = self
                .client
                .create_new_session(&api::CreateNewSessionArgs {
                    pubkeys: self.args.participants.clone(),
                    message_count: 1,
                })
                .await?;
            r.session_id
        } else {
            eprintln!("Joining DKG session...");
            match self.session_id {
                Some(s) => s,
                None => {
                    // Get session ID from server
                    let r = self.client.list_sessions().await?;
                    if r.session_ids.len() > 1 {
                        return Err(eyre!("user has more than one FROST session active; use `frost-client sessions` to list them and specify the session ID with `-S`").into());
                    } else if r.session_ids.is_empty() {
                        return Err(eyre!("User has no current sessions active").into());
                    }
                    r.session_ids[0]
                }
            }
        };
        self.session_id = Some(session_id);

        eprintln!("Getting session info...");
        // Get all participants' public keys, and derive their identifiers
        // from them.
        let session_info = self
            .client
            .get_session_info(&api::GetSessionInfoArgs { session_id })
            .await?;
        self.pubkeys = session_info
            .pubkeys
            .iter()
            .map(|p| {
                Ok((
                    p.clone(),
                    Identifier::<C>::derive(&[session_id.as_bytes(), &p.0[..]].concat())?,
                ))
            })
            .collect::<Result<_, frost_core::Error<C>>>()?;

        if self.pubkeys.len() < 2 {
            return Err(eyre!("DKG session must have at least 2 participants").into());
        }
        self.coordinator_pubkey = Some(session_info.coordinator_pubkey);

        // Copy the pubkeys into the state.
        match self.state {
            DKGSessionState::WaitingForRound1Packages {
                ref mut pubkeys, ..
            } => {
                *pubkeys = self.pubkeys.clone();
            }
            _ => unreachable!("wrong state"),
        }

        // Compute this user's identifier by deriving it from the concatenation
        // of the session ID and the communication public key.
        // This ensures the identifier is unique and that participants can
        // derive each other's identifiers.
        let input = [session_id.as_bytes(), &comm_pubkey.0[..]].concat();
        let identifier = Identifier::<C>::derive(&input)?;
        self.identifier = Some(identifier);
        Ok((identifier, self.pubkeys.len() as u16))
    }

    async fn get_threshold_and_description(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
    ) -> Result<(u16, Option<String>), Box<dyn Error>> {
        let (Some(comm_privkey), Some(comm_participant_pubkey_getter)) = (
            &self.args.comm_privkey,
            &self.args.comm_participant_pubkey_getter,
        ) else {
            return Err(
                eyre!("comm_privkey and comm_participant_pubkey_getter must be specified").into(),
            );
        };

        let cipher = Cipher::new(
            comm_privkey.clone(),
            self.pubkeys.keys().map(|pubkey| comm_participant_pubkey_getter(pubkey).ok_or_eyre(
                "A participant in specified FROST session is not registered in the user's address book"
            )).collect::<Result<_,_>>()?,
        )?;
        self.cipher = Some(cipher);
        let cipher = self.cipher.as_mut().expect("was just set");

        // The participant who created the session sends the DKG parameters to
        // the other participants. The messages are encrypted and authenticated
        // like all others, so the server can't change them.
        if !self.args.participants.is_empty() {
            let params = DKGParams {
                threshold: self
                    .args
                    .min_signers
                    .ok_or_eyre("threshold must be specified")?,
                description: self.args.description.clone(),
            };
            eprintln!("Sending the threshold and description to other participants...");
            for pubkey in self.pubkeys.clone().keys() {
                if Some(pubkey) == self.args.comm_pubkey.as_ref() {
                    continue;
                }
                let msg = cipher.encrypt(Some(pubkey), serde_json::to_vec(&params)?)?;
                self.client
                    .send(&api::SendArgs {
                        session_id: self.session_id.expect("set before"),
                        recipients: vec![pubkey.clone()],
                        msg,
                    })
                    .await?;
            }
            return Ok((params.threshold, params.description));
        }

        let coordinator_pubkey = self
            .coordinator_pubkey
            .clone()
            .expect("set in get_identifier_and_max_signers()");
        if Some(&coordinator_pubkey) == self.args.comm_pubkey.as_ref() {
            return Err(eyre!(
                "the DKG session was created by this user; specify the participants only when creating a new session"
            )
            .into());
        }
        if !self.pubkeys.contains_key(&coordinator_pubkey) {
            return Err(eyre!(
                "the user who created the DKG session is not one of its participants"
            )
            .into());
        }

        eprint!("Waiting for the session creator to send the threshold and description...");

        let params = loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .await?;
            let mut params: Option<DKGParams> = None;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                // The first message from the session creator must contain the
                // parameters. Other participants might have already received
                // them and sent their Round 1 Packages; keep them for later.
                if params.is_none() && msg.sender == coordinator_pubkey {
                    params = Some(serde_json::from_slice(&msg.msg).map_err(|_| {
                        eyre!("invalid DKG parameters received from the session creator (are all participants using the same frost-client version?)")
                    })?);
                } else {
                    self.pending_msgs.push(msg);
                }
            }
            if let Some(params) = params {
                break params;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
        };
        eprintln!();

        let max_signers = self.pubkeys.len();
        if params.threshold < 2 || params.threshold as usize > max_signers {
            return Err(eyre!(
                "invalid threshold received from the session creator: {} (must be at least 2 and at most the number of participants, {})",
                params.threshold,
                max_signers
            )
            .into());
        }
        if let Some(min_signers) = self.args.min_signers {
            if min_signers != params.threshold {
                return Err(eyre!(
                    "the threshold specified ({}) does not match the threshold sent by the session creator ({})",
                    min_signers,
                    params.threshold
                )
                .into());
            }
        }
        if let Some(description) = &params.description {
            // Don't allow the session creator to write control characters
            // (e.g. terminal escape sequences) into the config file or terminal.
            if description.chars().any(char::is_control) {
                return Err(eyre!("invalid description received from the session creator").into());
            }
        }
        // A description specified by the user takes precedence, since it is
        // only used locally to identify the group.
        let description = self.args.description.clone().or(params.description);

        eprintln!(
            "Using threshold {} of {} participants{}",
            params.threshold,
            max_signers,
            description
                .as_ref()
                .map(|d| format!(" and description \"{d}\""))
                .unwrap_or_default()
        );

        Ok((params.threshold, description))
    }

    async fn get_round1_packages(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        let cipher = self
            .cipher
            .as_mut()
            .expect("set in get_threshold_and_description()");

        // Handle messages received while waiting for the DKG parameters.
        for msg in std::mem::take(&mut self.pending_msgs) {
            self.state
                .recv(msg, self.identifier.expect("must have been set"))?;
        }

        // Send Round 1 Package to all other participants
        for pubkey in self.pubkeys.clone().keys() {
            if Some(pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = cipher.encrypt(Some(pubkey), serde_json::to_vec(&round1_package)?)?;
            self.client
                .send(&api::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![pubkey.clone()],
                    msg,
                })
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 1 Packages...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state
                    .recv(msg, self.identifier.expect("must have been set"))?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round1_packages() {
                break;
            }
        }
        eprintln!();

        // We might need to skip the echo broadcast if its not needed (e.g.
        // only 2 participants)
        if !self.state.has_round1_broadcast_packages() {
            // Broadcast received Round 1 Packages to all other participants
            for (recipient_pubkey, recipient_identifier) in self.pubkeys.clone().iter() {
                // No need to broadcast to oneself
                if Some(recipient_pubkey) == self.args.comm_pubkey.as_ref() {
                    continue;
                }
                for (sender_identifier, package) in self.state.round1_packages()?.iter() {
                    // No need to broadcast back to the sender
                    if *sender_identifier == *recipient_identifier {
                        continue;
                    }
                    let msg = cipher.encrypt(
                        Some(recipient_pubkey),
                        serde_json::to_vec(&(*sender_identifier, package))?,
                    )?;
                    self.client
                        .send(&api::SendArgs {
                            session_id: self.session_id.expect("set before"),
                            recipients: vec![recipient_pubkey.clone()],
                            msg,
                        })
                        .await?;
                }
            }

            eprint!("Waiting for other participants to send their broadcasted Round 1 Packages...");

            loop {
                let r = self
                    .client
                    .receive(&api::ReceiveArgs {
                        session_id: self.session_id.unwrap(),
                        as_coordinator: false,
                    })
                    .await?;
                for msg in r.msgs {
                    let msg = cipher.decrypt(msg)?;
                    self.state
                        .recv(msg, self.identifier.expect("must have been set"))?;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
                if self.state.has_round1_broadcast_packages() {
                    break;
                }
            }
            eprintln!();
        }

        self.state.round1_packages()
    }

    async fn get_round2_packages(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        let cipher = self.cipher.as_mut().expect("was just set");
        // Send Round 2 Packages to all other participants
        for (pubkey, identifier) in self.pubkeys.clone().into_iter() {
            if Some(&pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = cipher.encrypt(
                Some(&pubkey),
                serde_json::to_vec(
                    &round2_packages
                        .get(&identifier)
                        .ok_or_eyre("must have Round 2 Package for the given identifier")?,
                )?,
            )?;
            self.client
                .send(&api::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![pubkey.clone()],
                    msg,
                })
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 2 Packages...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state
                    .recv(msg, self.identifier.expect("must have been set"))?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round2_packages() {
                break;
            }
        }
        eprintln!();

        if !self.args.participants.is_empty() {
            let _r = self
                .client
                .close_session(&api::CloseSessionArgs {
                    session_id: self.session_id.unwrap(),
                })
                .await?;
        }

        let _r = self.client.logout().await?;

        self.state.round2_packages()
    }

    fn get_pubkey_identifier_map(
        &self,
    ) -> Result<HashMap<PublicKey, Identifier<C>>, Box<dyn Error>> {
        match &self.state {
            DKGSessionState::Round2PackagesReady { pubkeys, .. } => Ok(pubkeys.clone()),
            _ => Err(eyre!("wrong state").into()),
        }
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session_id) = self.session_id {
            let _r = self
                .client
                .close_session(&api::CloseSessionArgs { session_id })
                .await?;
        }
        Ok(())
    }
}
