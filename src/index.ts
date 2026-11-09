import { Experimental } from "@foxglove/extension";

// Webpack inlines this import as a base64 data URL, so the compiled .wasm
// travels inside the .foxe archive.
import wasmUrl from "../rust/target/wasm32-unknown-unknown/release/cyberrecord.wasm";

export function activate(extensionContext: Experimental.ExtensionContext): void {
  extensionContext.registerDataLoader({
    type: "file",
    wasmUrl,
    supportedFileType: ".record",
    // Apollo splits long recordings into segments. Files renamed to .record
    // can be opened together and are merged into one timeline.
    supportsMultiFile: true,
  });
}
