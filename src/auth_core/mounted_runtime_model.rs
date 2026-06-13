use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::Keyset;
use crate::db::{WritePool, queue};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::Body;
use http_body_util::BodyExt;
use serde::Deserialize;
use tower_layer::Layer;
use tower_service::Service;

use super::email_otp_method::{EMAIL_OTP_METHOD_LABEL, PostgresEmailOtpSubjectResolver};
use super::postgres_method_runtime::{
    PostgresAuthMethodMountedRouteCapabilities, PostgresAuthMethodRegistry,
};
use super::postgres_password_derived_signature_method::PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL;
use super::postgres_recovery_code_method::RECOVERY_CODE_METHOD_LABEL;
use super::postgres_runtime::{AuthPostgresWebRuntimeExecutionError, PostgresAuthWebRuntime};
use super::postgres_totp_method::{
    PostgresTotpCodeVerifier, StandardTotpCodeVerifier, TOTP_METHOD_LABEL,
};
use super::prelude::*;

mod body_parsing;
mod errors;
mod http_service;
mod protected_layers;
mod response_rendering;
mod route_execution;
mod route_guarding;
mod route_manifest;
mod route_service;
mod route_types;
mod system_config;
mod system_services;

pub(crate) use body_parsing::*;
pub(crate) use errors::*;
pub(crate) use http_service::*;
pub(crate) use protected_layers::*;
use response_rendering::*;
pub(crate) use route_guarding::*;
pub(crate) use route_manifest::*;
use route_service::*;
pub(crate) use route_types::*;
pub(crate) use system_config::*;
pub(crate) use system_services::*;
