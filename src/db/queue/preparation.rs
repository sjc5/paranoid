use super::*;
use std::io::{self, Write};

pub(super) struct PreparedEnqueue {
    pub(super) job_id: JobId,
    pub(super) task_name: String,
    pub(super) payload_json: String,
    pub(super) run_at_or_after_unix_microseconds: Option<i64>,
    pub(super) max_retries: i32,
    pub(super) timeout_nanos: i64,
    pub(super) dedupe_key: Option<String>,
}

impl PreparedEnqueue {
    #[cfg(test)]
    pub(super) fn new<T: Serialize + ?Sized>(
        task_name: &str,
        payload: &T,
        options: EnqueueOptions,
    ) -> Result<Self, Error> {
        Self::new_with_payload_json_limit(
            task_name,
            payload,
            options,
            DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        )
    }

    pub(super) fn new_with_payload_json_limit<T: Serialize + ?Sized>(
        task_name: &str,
        payload: &T,
        options: EnqueueOptions,
        payload_json_limit_bytes: usize,
    ) -> Result<Self, Error> {
        validate_payload_json_limit_bytes(payload_json_limit_bytes)?;
        validate_task_name(task_name)?;
        validate_optional_dedupe_key(options.dedupe_key.as_deref())?;

        let max_retries = options
            .max_retries
            .unwrap_or(DEFAULT_QUEUE_MAX_RETRIES)
            .try_into()
            .map_err(|_| Error::InvalidMaxRetries)?;
        let timeout_nanos = timeout_to_nanos(options.timeout)?;
        let payload_json = serialize_payload_json(payload, payload_json_limit_bytes)
            .map_err(PayloadJsonSerializationError::into_single_payload_error)?;

        Ok(Self {
            job_id: JobId::new()?,
            task_name: task_name.to_owned(),
            payload_json,
            run_at_or_after_unix_microseconds: options
                .run_at_or_after
                .map(JobRunAtOrAfter::as_unix_microseconds),
            max_retries,
            timeout_nanos,
            dedupe_key: options.dedupe_key,
        })
    }
}

pub(super) struct PreparedBatchEnqueueJob {
    pub(super) job_id: JobId,
    pub(super) payload_json: String,
}

pub(super) struct PreparedEnqueueBatch {
    pub(super) task_name: String,
    pub(super) jobs: Vec<PreparedBatchEnqueueJob>,
    pub(super) run_at_or_after_unix_microseconds: Option<i64>,
    pub(super) max_retries: i32,
    pub(super) timeout_nanos: i64,
}

impl PreparedEnqueueBatch {
    #[cfg(test)]
    pub(super) fn new<T: Serialize>(
        task_name: &str,
        payloads: &[T],
        options: EnqueueBatchOptions,
    ) -> Result<Self, Error> {
        Self::new_with_payload_json_limit(
            task_name,
            payloads,
            options,
            DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        )
    }

    pub(super) fn new_with_payload_json_limit<T: Serialize>(
        task_name: &str,
        payloads: &[T],
        options: EnqueueBatchOptions,
        payload_json_limit_bytes: usize,
    ) -> Result<Self, Error> {
        validate_payload_json_limit_bytes(payload_json_limit_bytes)?;
        validate_task_name(task_name)?;
        validate_enqueue_batch_size(payloads.len())?;

        let max_retries = options
            .max_retries
            .unwrap_or(DEFAULT_QUEUE_MAX_RETRIES)
            .try_into()
            .map_err(|_| Error::InvalidMaxRetries)?;
        let timeout_nanos = timeout_to_nanos(options.timeout)?;

        let mut jobs = Vec::with_capacity(payloads.len());
        for (payload_index, payload) in payloads.iter().enumerate() {
            let payload_json = serialize_payload_json(payload, payload_json_limit_bytes)
                .map_err(|error| error.into_batch_payload_error(payload_index))?;
            jobs.push(PreparedBatchEnqueueJob {
                job_id: JobId::new()?,
                payload_json,
            });
        }

        Ok(Self {
            task_name: task_name.to_owned(),
            jobs,
            run_at_or_after_unix_microseconds: options
                .run_at_or_after
                .map(JobRunAtOrAfter::as_unix_microseconds),
            max_retries,
            timeout_nanos,
        })
    }
}

enum PayloadJsonSerializationError {
    Json(serde_json::Error),
    TooLarge { actual_minimum: usize, max: usize },
}

impl PayloadJsonSerializationError {
    fn into_single_payload_error(self) -> Error {
        match self {
            Self::Json(source) => Error::PayloadJson { source },
            Self::TooLarge {
                actual_minimum,
                max,
            } => Error::PayloadJsonTooLarge {
                actual_minimum,
                max,
            },
        }
    }

    fn into_batch_payload_error(self, payload_index: usize) -> Error {
        match self {
            Self::Json(source) => Error::EnqueueBatchPayloadJson {
                payload_index,
                source,
            },
            Self::TooLarge {
                actual_minimum,
                max,
            } => Error::EnqueueBatchPayloadJsonTooLarge {
                payload_index,
                actual_minimum,
                max,
            },
        }
    }
}

fn serialize_payload_json<T: Serialize + ?Sized>(
    payload: &T,
    payload_json_limit_bytes: usize,
) -> Result<String, PayloadJsonSerializationError> {
    let mut writer = PayloadJsonLimitWriter::new(payload_json_limit_bytes);
    match serde_json::to_writer(&mut writer, payload) {
        Ok(()) => Ok(String::from_utf8(writer.into_bytes()).expect("serde_json writes UTF-8")),
        Err(_) if writer.exceeded_limit().is_some() => {
            let actual_minimum = writer
                .exceeded_limit()
                .expect("limit should be recorded after limit error");
            Err(PayloadJsonSerializationError::TooLarge {
                actual_minimum,
                max: payload_json_limit_bytes,
            })
        }
        Err(source) => Err(PayloadJsonSerializationError::Json(source)),
    }
}

struct PayloadJsonLimitWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded_limit_at: Option<usize>,
}

impl PayloadJsonLimitWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded_limit_at: None,
        }
    }

    fn exceeded_limit(&self) -> Option<usize> {
        self.exceeded_limit_at
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for PayloadJsonLimitWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next_len = self.bytes.len().saturating_add(buf.len());
        if next_len > self.limit {
            self.exceeded_limit_at = Some(next_len);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "queue payload JSON too large",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
