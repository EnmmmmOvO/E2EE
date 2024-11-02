use std::sync::{Arc, Mutex};
use crate::message::Message;

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub ikp: Vec<u8>,
    pub spk: Vec<u8>,
    pub spk_sig: Vec<u8>,
    pub opk: Vec<u8>,
    message: Arc<Mutex<Vec<Message>>>,
}

impl Session {
    pub fn new(target: &str, ikp: Vec<u8>, spk: Vec<u8>, spk_sig: Vec<u8>, opk: Vec<u8>) -> Self {
        Self { target: target.to_string(), ikp, spk, spk_sig, opk, message: Arc::new(Mutex::new(vec![])) }
    }
    
    pub fn name(&self) -> &str {
        &self.target
    }
    
    pub fn message(&self) -> Arc<Mutex<Vec<Message>>> {
        self.message.clone()
    }
    
    pub fn add_message(&self, message: Message) {
        let mut messages = self.message.lock().unwrap();
        messages.push(message);
    }
}