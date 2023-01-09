use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct Topic {
    message: String,
    id: u64,
}

#[near_bindgen]
impl Topic {
    // view()
    pub fn show_id(&self) -> u64 {
        self.id
    }

    // view(a) -> X
    pub fn show_type(&self, is_message: bool) -> String {
        if is_message {
            format!("Message: {}", self.message)
        } else {
            format!("ID: {}", self.id)
        }
    }

    // function_call() -> no return values
    pub fn increment(&mut self) {
        self.id += 1;
    }

    // function_call(a) -> X
    pub fn change_message(&mut self, message: String) -> String {
        self.message = message;
        self.message.clone()
    }

    // function_call(a) -> X
    pub fn change_id(&mut self, id: u64) -> u64 {
        self.id = id;
        self.id
    }
}
