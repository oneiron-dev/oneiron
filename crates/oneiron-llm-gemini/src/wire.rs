//! Gemini generateContent request and response mapping plus status taxonomy.
use oneiron::llm::BudgetDenied;
use oneiron::{ContentPart,ImageContent,LlmMessageRole,LlmRequest,LlmResult,LlmResponse,LlmCatalogEntry,ResponseFormat,LlmError,FatalLlmError,RetryableLlmError,LlmStreamEvent};
use serde_json::{Value,json};
use super::{GeminiHttpRequest,GeminiAccumulator};
pub fn build_request(entry:&LlmCatalogEntry,request:&LlmRequest,stream:bool)->LlmResult<GeminiHttpRequest>{
    entry.admit(request,stream)?;
    let calls:std::collections::BTreeMap<_,_>=request.messages.iter().flat_map(|m|&m.content).filter_map(|part|match part {ContentPart::ToolCall{call_id,name,..}=>Some((call_id.as_str(),name.as_str())),_=>None}).collect();
    let mut contents=Vec::new();let mut system=Vec::new();
    for message in &request.messages {
        let parts=message.content.iter().map(|part|encode_part(part,&calls)).collect::<LlmResult<Vec<_>>>()?;
        if message.role==LlmMessageRole::System {system.extend(parts);}else{contents.push(json!({"role":if message.role==LlmMessageRole::Assistant {"model"}else{"user"},"parts":parts}));}
    }
    let mut generation=serde_json::Map::new();
    for (name,value) in &request.params {
        let wire_name=match name.as_str(){"max_tokens"=>"maxOutputTokens","top_p"=>"topP","top_k"=>"topK","presence_penalty"=>"presencePenalty","frequency_penalty"=>"frequencyPenalty",other=>other};
        generation.insert(wire_name.into(),value.clone());
    }
    if let ResponseFormat::Json{schema}=&request.envelope.response_format{generation.insert("responseMimeType".into(),json!("application/json"));generation.insert("responseJsonSchema".into(),schema.clone());}
    let mut body=json!({"contents":contents,"generationConfig":generation});
    if !system.is_empty(){body["systemInstruction"]=json!({"parts":system});}
    if !request.tools.is_empty(){body["tools"]=json!([{"functionDeclarations":request.tools.iter().map(|tool|json!({"name":tool.name,"description":tool.description,"parametersJsonSchema":tool.input_schema})).collect::<Vec<_>>()}]);}
    if let Some(options)=request.provider_options.get("gemini") {
        let options=options.as_object().ok_or(FatalLlmError::InvalidRequest)?;
        for (name,value) in options {if !matches!(name.as_str(),"safetySettings"|"toolConfig"|"cachedContent"){return Err(FatalLlmError::InvalidRequest.into());}body[name]=value.clone();}
    }
    let model=entry.metadata.get("wire_model").and_then(Value::as_str).unwrap_or_else(||request.model.name());
    if !model.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'|b'.')){return Err(FatalLlmError::InvalidRequest.into());}
    Ok(GeminiHttpRequest{path:format!("/v1beta/models/{model}:{}",if stream{"streamGenerateContent?alt=sse"}else{"generateContent"}),body})
}
fn encode_part(part:&ContentPart,calls:&std::collections::BTreeMap<&str,&str>)->LlmResult<Value>{Ok(match part {
    ContentPart::Text{text}=>json!({"text":text}),
    ContentPart::Reasoning{text,signature}=>{let mut v=json!({"text":text,"thought":true});if let Some(s)=signature{v["thoughtSignature"]=json!(s);}v},
    ContentPart::ToolCall{call_id,name,input}=>json!({"functionCall":{"id":call_id,"name":name,"args":input}}),
    ContentPart::ToolResult{call_id,output,is_error}=>json!({"functionResponse":{"id":call_id,"name":calls.get(call_id.as_str()).ok_or(FatalLlmError::InvalidRequest)?,"response":{"output":output,"is_error":is_error}}}),
    ContentPart::Image{media_type,image:ImageContent::Base64{data}}=>json!({"inlineData":{"mimeType":media_type,"data":data}}),
    ContentPart::Image{media_type,image:ImageContent::Url{url}}=>json!({"fileData":{"mimeType":media_type,"fileUri":url}}),
})}
pub fn parse_response(mut body:Value)->LlmResult<LlmResponse>{
    if body.pointer("/candidates/0/finishReason").is_none(){if let Some(candidate)=body.pointer_mut("/candidates/0"){candidate["finishReason"]=json!("STOP");}}
    let events=GeminiAccumulator::default().push(body)?;
    events.into_iter().find_map(|e|match e{LlmStreamEvent::Done{message,usage,finish_reason}=>Some(LlmResponse{message,usage,finish_reason}),_=>None}).ok_or_else(||FatalLlmError::EmptyResponse.into())
}
pub fn classify_status(status:u16,body:&Value)->LlmError{
    if status==402 || body.pointer("/error/status").and_then(Value::as_str)==Some("BUDGET_EXCEEDED"){return BudgetDenied::AdmissionDenied.into();}
    match status{401|403=>FatalLlmError::Auth.into(),408|504=>RetryableLlmError::Timeout.into(),429=>RetryableLlmError::RateLimited{retry_after:None}.into(),500..=599=>RetryableLlmError::ServerError.into(),_=>FatalLlmError::InvalidRequest.into()}
}
