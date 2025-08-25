// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Named futures returned from methods on types in
//! [the `encryption` module][super].

#![deny(unreachable_pub)]

use std::future::IntoFuture;

use eyeball::{SharedObservable, Subscriber};
use matrix_sdk_common::boxed_into_future;
use ruma::events::room::{EncryptedFile, EncryptedFileInit};

use super::EncryptedBytes;
use crate::{config::RequestConfig, Client, Media, Result, TransmissionProgress};

/// Future returned by [`Client::upload_encrypted_file`].
#[allow(missing_debug_implementations)]
pub struct UploadEncryptedFile<'a> {
    client: &'a Client,
    encrypted_bytes: EncryptedBytes,
    send_progress: SharedObservable<TransmissionProgress>,
    request_config: Option<RequestConfig>,
}

impl<'a> UploadEncryptedFile<'a> {
    pub(crate) fn new(client: &'a Client, encrypted_bytes: EncryptedBytes) -> Self {
        Self { client, encrypted_bytes, send_progress: Default::default(), request_config: None }
    }

    /// Replace the default `SharedObservable` used for tracking upload
    /// progress.
    ///
    /// Note that any subscribers obtained from
    /// [`subscribe_to_send_progress`][Self::subscribe_to_send_progress]
    /// will be invalidated by this.
    pub fn with_send_progress_observable(
        mut self,
        send_progress: SharedObservable<TransmissionProgress>,
    ) -> Self {
        self.send_progress = send_progress;
        self
    }

    /// Replace the default request config used for the upload request.
    ///
    /// The timeout value will be overridden with a reasonable default, based on
    /// the size of the encrypted payload.
    pub fn with_request_config(mut self, request_config: RequestConfig) -> Self {
        self.request_config = Some(request_config);
        self
    }

    /// Get a subscriber to observe the progress of sending the request
    /// body.
    pub fn subscribe_to_send_progress(&self) -> Subscriber<TransmissionProgress> {
        self.send_progress.subscribe()
    }
}

impl<'a> IntoFuture for UploadEncryptedFile<'a> {
    type Output = Result<EncryptedFile>;
    boxed_into_future!(extra_bounds: 'a);

    fn into_future(self) -> Self::IntoFuture {
        let Self { client, mut encrypted_bytes, send_progress, request_config } = self;
        Box::pin(async move {
            // Override the reasonable upload timeout value, based on the size of the
            // encrypted payload.
            let request_config = request_config.map(|config| {
                config.timeout(Media::reasonable_upload_timeout(&encrypted_bytes.bytes))
            });

            let response = client
                .media()
                .upload(&mime::APPLICATION_OCTET_STREAM, encrypted_bytes.bytes, request_config)
                .with_send_progress_observable(send_progress)
                .await?;

            let file: EncryptedFile = {
                EncryptedFileInit {
                    url: response.content_uri,
                    key: encrypted_bytes.info.key,
                    iv: encrypted_bytes.info.iv,
                    hashes: encrypted_bytes.info.hashes,
                    v: encrypted_bytes.info.version,
                }
                .into()
            };

            Ok(file)
        })
    }
}
