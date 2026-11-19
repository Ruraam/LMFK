#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! ABI v1 de LMFK : contrat binaire entre le noyau et les pilotes.
//!
//! Cette crate ne contient aucune implementation noyau. Elle ne definit que
//! des types a representation explicite (`repr(C)`, alignement force, champs
//! de taille en tete) et les regles de versionnage.
//!
//! Regles :
//! - aucun pointeur vers le noyau dans les structures : seulement des
//!   [`Handle`] opaques de 64 bits (0 = invalide) ;
//! - aucun type dependant de l'architecture (`usize`, `isize`, enum Rust) ;
//! - compatibilite ascendante par `size`, ajout en fin de structure et
//!   ajout en fin de table de fonctions ;
//! - les pointeurs de fonction sont `Option` : `None` = fonction absente.

pub mod api;
pub mod handle;
pub mod status;
pub mod types;
pub mod version;

pub use api::{DriverApi, DriverEntry, DriverEntryPoint};
pub use handle::Handle;
pub use status::Status;
pub use types::{Bus, DEVICE_NAME_LEN, DeviceDesc};
pub use version::{
    ABI_ANY_MINOR, ABI_V1, ABI_VERSION, VersionRange, abi_major, abi_minor, is_compatible,
    make_version,
};

/// Assertions de mise en page verifiees a la compilation.
///
/// Elles garantissent que le code Rust et le header C (`include/lmfk/abi.h`)
/// restent synchrones. Les memes valeurs sont reverifiees par
/// `tests/abi_layout.c` et `tests/layout.rs`.
mod layout_assertions {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    const _: () = assert!(size_of::<Handle>() == 8);
    const _: () = assert!(size_of::<Status>() == 4);
    const _: () = assert!(size_of::<Bus>() == 2);

    const _: () = assert!(size_of::<DeviceDesc>() == 96);
    const _: () = assert!(align_of::<DeviceDesc>() == 8);
    const _: () = assert!(offset_of!(DeviceDesc, bus) == 4);
    const _: () = assert!(offset_of!(DeviceDesc, name) == 32);

    const _: () = assert!(size_of::<DriverApi>() == 96);
    const _: () = assert!(align_of::<DriverApi>() == 8);
    const _: () = assert!(offset_of!(DriverApi, abi_version) == 4);
    const _: () = assert!(offset_of!(DriverApi, log) == 8);
    const _: () = assert!(offset_of!(DriverApi, mmio_map) == 32);
    const _: () = assert!(offset_of!(DriverApi, device_write) == 88);

    const _: () = assert!(size_of::<DriverEntry>() == 80);
    const _: () = assert!(align_of::<DriverEntry>() == 8);
    const _: () = assert!(offset_of!(DriverEntry, init) == 8);
    const _: () = assert!(offset_of!(DriverEntry, shutdown) == 72);
}
