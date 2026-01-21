//! Security analysis modules.

mod benchmark;
mod name_resolution;
mod queries;
mod sast;
mod sca;
mod secrets;
mod taint;

pub use benchmark::*;
pub use name_resolution::*;
pub use queries::*;
pub use sast::*;
pub use sca::*;
pub use secrets::*;
pub use taint::*;
