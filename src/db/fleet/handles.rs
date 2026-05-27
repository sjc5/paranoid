use super::*;

impl<E> SubscriptionRunHandle<E> {
    /// Requests a clean stop. Returns true if the background task had not already been stopped.
    pub fn request_stop(&mut self) -> bool {
        send_stop_signal(&mut self.stop_sender)
    }

    /// Returns whether the background task has finished.
    pub fn is_finished(&self) -> bool {
        match self.join_handle.as_ref() {
            Some(join_handle) => join_handle.is_finished(),
            None => true,
        }
    }

    /// Waits for the background task to finish.
    pub async fn wait(mut self) -> Result<(), SubscriptionRunHandleError<E>> {
        let Some(join_handle) = self.join_handle.take() else {
            return Ok(());
        };
        match join_handle.await {
            Ok(result) => result.map_err(|source| SubscriptionRunHandleError::Run { source }),
            Err(source) => Err(SubscriptionRunHandleError::Join { source }),
        }
    }

    /// Requests a clean stop, then waits for the background task to finish.
    pub async fn stop_and_wait(mut self) -> Result<(), SubscriptionRunHandleError<E>> {
        self.request_stop();
        self.wait().await
    }
}

impl<E> Drop for SubscriptionRunHandle<E> {
    fn drop(&mut self) {
        self.request_stop();
    }
}

impl<E> CronRunHandle<E> {
    /// Requests a clean stop. Returns true if the background task had not already been stopped.
    pub fn request_stop(&mut self) -> bool {
        send_stop_signal(&mut self.stop_sender)
    }

    /// Returns whether the background task has finished.
    pub fn is_finished(&self) -> bool {
        match self.join_handle.as_ref() {
            Some(join_handle) => join_handle.is_finished(),
            None => true,
        }
    }

    /// Waits for the background task to finish.
    pub async fn wait(mut self) -> Result<(), CronRunHandleError<E>> {
        let Some(join_handle) = self.join_handle.take() else {
            return Ok(());
        };
        match join_handle.await {
            Ok(result) => result.map_err(|source| CronRunHandleError::Run { source }),
            Err(source) => Err(CronRunHandleError::Join { source }),
        }
    }

    /// Requests a clean stop, then waits for the background task to finish.
    pub async fn stop_and_wait(mut self) -> Result<(), CronRunHandleError<E>> {
        self.request_stop();
        self.wait().await
    }
}

impl<E> Drop for CronRunHandle<E> {
    fn drop(&mut self) {
        self.request_stop();
    }
}
