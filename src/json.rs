use serde_json::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    model : i32,
    y: i32,
}


pub fn parse(s:Value)->String{
    "".to_string()
}