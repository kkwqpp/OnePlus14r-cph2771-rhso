#[cfg(target_arch = "wasm32")]
mod browser;
pub mod core;

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::core;
    use serde_json::Value;
    use wasm_bindgen::prelude::*;
    fn parse(value: &str) -> Result<Value, JsValue> {
        serde_json::from_str(value).map_err(|_| JsValue::from_str("Invalid marshalled UI value."))
    }
    fn result(value: Result<Value, String>) -> Result<String, JsValue> {
        value
            .map(|v| v.to_string())
            .map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn policy_json() -> String {
        serde_json::json!({"targets":core::TARGETS,"states":core::STATES,"profiles":{"hma-scope":core::profile_name("hma-scope"),"brezygisk-unmount":core::profile_name("brezygisk-unmount")}}).to_string()
    }
    #[wasm_bindgen]
    pub fn encode_request(command: &str, args: &str) -> Result<String, JsValue> {
        core::encode_request(command, &parse(args)?).map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn read_result(stdout: &str) -> Result<String, JsValue> {
        core::read_result(stdout)
            .map(|r| serde_json::to_string(&r).unwrap())
            .map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn safe_text(value: &str, fallback: &str) -> String {
        core::safe_text(
            &serde_json::from_str(value).unwrap_or(Value::Null),
            fallback,
        )
    }
    #[wasm_bindgen]
    pub fn list_json(value: &str) -> Result<String, JsValue> {
        Ok(Value::Array(core::list(&parse(value)?).to_vec()).to_string())
    }
    #[wasm_bindgen]
    pub fn selection_value(
        id: &str,
        box_index: f64,
        key_index: f64,
        algorithm: &str,
    ) -> Result<String, JsValue> {
        core::selection_value(id, box_index, key_index, algorithm)
            .map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn compaction_counts(value: &str) -> Result<String, JsValue> {
        result(core::compaction_counts(&parse(value)?))
    }
    #[wasm_bindgen]
    pub fn private_api_path(value: &str) -> Result<String, JsValue> {
        core::private_api_path(value)
            .map(str::to_owned)
            .map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn api_status_view(value: &str) -> Result<String, JsValue> {
        Ok(core::api_status_view(&parse(value)?)
            .unwrap_or(Value::Null)
            .to_string())
    }
    #[wasm_bindgen]
    pub fn redact_api(value: &str) -> Result<String, JsValue> {
        Ok(core::redact_api_value(&parse(value)?).to_string())
    }
    #[wasm_bindgen]
    pub fn stack_status_view(value: &str) -> Result<String, JsValue> {
        Ok(core::stack_status_view(&parse(value)?)
            .unwrap_or(Value::Null)
            .to_string())
    }
    #[wasm_bindgen]
    pub fn stack_package_list(value: &str) -> Result<String, JsValue> {
        core::stack_package_list(value)
            .map(|v| serde_json::to_string(&v).unwrap())
            .map_err(|s| JsValue::from_str(&s))
    }
    #[wasm_bindgen]
    pub fn stack_plan_view(value: &str) -> Result<String, JsValue> {
        result(core::stack_plan_view(&parse(value)?))
    }
    #[wasm_bindgen]
    pub fn redact_stack(value: &str) -> Result<String, JsValue> {
        Ok(core::redact_stack_value(&parse(value)?).to_string())
    }
    #[wasm_bindgen]
    pub fn evidence_binding(value: &str) -> Result<String, JsValue> {
        Ok(core::evidence_binding(&parse(value)?)
            .map(Value::String)
            .unwrap_or(Value::Null)
            .to_string())
    }
}
