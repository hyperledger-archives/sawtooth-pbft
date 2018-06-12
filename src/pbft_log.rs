use protos::pbft_message::{PbftMessage, PbftViewChange, PbftNewView};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct PbftLogError;

impl Error for PbftLogError {
    // TODO: Fill this out
    fn description(&self) -> &str {
        "Log error"
    }
}

impl fmt::Display for PbftLogError {
    // TODO: Fill this out
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[derive(Debug)]
pub struct PbftLog {
    messages: Vec<PbftMessage>,
    view_changes: Vec<PbftViewChange>,
    new_views: Vec<PbftNewView>,
}

impl PbftLog {
    pub fn new() -> Self {
        PbftLog {
            messages: vec![],
            view_changes: vec![],
            new_views: vec![]
        }
    }

    // Methods for dealing with PbftMessages
    pub fn add_message(&mut self, msg: PbftMessage) -> Result<(), PbftLogError> {
        self.messages.push(msg);
        Ok(())
    }

    pub fn get_messages_of_type(
        &self,
        msg_type: &str,
        sequence_number: u64,
    ) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| {
                (*msg).get_info().get_msg_type() == msg_type &&
                    (*msg).get_info().get_seq_num() == sequence_number
            })
            .collect();
        Ok(msgs)
    }

    // Methods for dealing with PbftViewChanges
    pub fn add_view_change(&mut self, vc: PbftViewChange) -> Result<(), PbftLogError> {
        self.view_changes.push(vc);
        Ok(())
    }

    pub fn get_view_change(
        &self,
        sequence_number: u64,
    ) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
            .collect();
        Ok(msgs)
    }

    // Methods for dealing with PbftNewViews
    pub fn add_new_view(&mut self, vc: PbftViewChange) -> Result<(), PbftLogError> {
        self.view_changes.push(vc);
        Ok(())
    }

    pub fn get_new_view(
        &self,
        sequence_number: u64,
    ) -> Result<Vec<&PbftMessage>, PbftLogError> {
        let msgs: Vec<&PbftMessage> = self.messages
            .iter()
            .filter(|&msg| (*msg).get_info().get_seq_num() == sequence_number)
            .collect();
        Ok(msgs)
    }
}
