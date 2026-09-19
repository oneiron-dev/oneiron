//! Lease-bearing host transport; no SDK, retries, or call policy.
use std::{future::Future,pin::Pin};
use futures_core::Stream;
use oneiron::{BudgetLease,LlmResult,LlmUsage};
use serde_json::Value;
#[derive(Debug,Clone,PartialEq)]
pub struct GeminiHttpRequest { pub path:String,pub body:Value }
#[derive(Debug,Clone,PartialEq)]
pub struct GeminiHttpResponse { pub status:u16,pub body:Value }
#[derive(Debug,Clone,PartialEq)]
pub enum GeminiFrame { Chunk(Value), Status(GeminiHttpResponse), Abort(LlmUsage) }
pub type GeminiFuture<'a>=Pin<Box<dyn Future<Output=LlmResult<GeminiHttpResponse>>+Send+'a>>;
pub type GeminiProviderStream<'a>=Pin<Box<dyn Stream<Item=LlmResult<GeminiFrame>>+Send+'a>>;
pub trait GeminiTransport:Send+Sync {
    fn execute<'a>(&'a self,request:GeminiHttpRequest,lease:&'a BudgetLease)->GeminiFuture<'a>;
    fn stream<'a>(&'a self,request:GeminiHttpRequest,lease:&'a BudgetLease)->LlmResult<GeminiProviderStream<'a>>;
}
