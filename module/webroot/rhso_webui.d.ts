/* tslint:disable */
/* eslint-disable */

export function api_status_view(value: string): string;

export function compaction_counts(value: string): string;

export function encode_request(command: string, args: string): string;

export function evidence_binding(value: string): string;

export function list_json(value: string): string;

export function policy_json(): string;

export function private_api_path(value: string): string;

export function read_result(stdout: string): string;

export function redact_api(value: string): string;

export function redact_stack(value: string): string;

export function safe_text(value: string, fallback: string): string;

export function selection_value(id: string, box_index: number, key_index: number, algorithm: string): string;

export function stack_package_list(value: string): string;

export function stack_plan_view(value: string): string;

export function stack_status_view(value: string): string;

/**
 * Called once by the small loader after explicit-byte WASM initialization.
 */
export function start_ui(bridge: Function): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly start_ui: (a: number, b: number) => void;
    readonly policy_json: (a: number) => void;
    readonly encode_request: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly read_result: (a: number, b: number, c: number) => void;
    readonly safe_text: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly list_json: (a: number, b: number, c: number) => void;
    readonly selection_value: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly compaction_counts: (a: number, b: number, c: number) => void;
    readonly private_api_path: (a: number, b: number, c: number) => void;
    readonly api_status_view: (a: number, b: number, c: number) => void;
    readonly redact_api: (a: number, b: number, c: number) => void;
    readonly stack_status_view: (a: number, b: number, c: number) => void;
    readonly stack_package_list: (a: number, b: number, c: number) => void;
    readonly stack_plan_view: (a: number, b: number, c: number) => void;
    readonly redact_stack: (a: number, b: number, c: number) => void;
    readonly evidence_binding: (a: number, b: number, c: number) => void;
    readonly __wasm_bindgen_func_elem_60: (a: number, b: number) => void;
    readonly __wasm_bindgen_func_elem_734: (a: number, b: number) => void;
    readonly __wasm_bindgen_func_elem_217: (a: number, b: number, c: number) => void;
    readonly __wasm_bindgen_func_elem_746: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
