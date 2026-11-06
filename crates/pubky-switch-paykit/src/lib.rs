//! The Paykit v0.2 profile of the Pubky Switch.
//!
//! Everything the Switch needs to know that is specific to Paykit lives here, so that the
//! service itself stays protocol-neutral:
//!
//! - the scope names and the Switch permissions each one grants (wire 3.1);
//! - the fixed record policies of Paykit's shared record collections (wire 6.1);
//! - Paykit's message kinds and the scopes they map to (spec 3.4).
//!
//! The protocol's types, encodings and signatures come from `paykit-lib`; this crate only
//! configures the Switch with them.
