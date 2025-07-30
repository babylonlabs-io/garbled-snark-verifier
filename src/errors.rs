use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SystemMetricError {
    #[error("Failed to get disk space: {0}")]
    DiskSpaceError(String),
    
    #[error("Failed to get memory stats: {0}")]
    MemoryError(String),
    
    #[error("Command execution failed: {0}")]
    CommandError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("All retry attempts failed")]
    RetryExhausted,
}

/// Retry configuration for system metric collection
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: usize,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
        }
    }
}

/// Execute a function with exponential backoff retry logic
pub async fn retry_with_backoff<T, F, E>(
    mut operation: F,
    config: &RetryConfig,
) -> Result<T, SystemMetricError>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let mut delay = config.initial_delay;
    
    for attempt in 1..=config.max_attempts {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::warn!("Attempt {}/{} failed: {}", attempt, config.max_attempts, e);
                
                if attempt == config.max_attempts {
                    return Err(SystemMetricError::RetryExhausted);
                }
                
                std::thread::sleep(delay);
                delay = std::cmp::min(
                    Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                    config.max_delay,
                );
            }
        }
    }
    
    Err(SystemMetricError::RetryExhausted)
}

/// Synchronous version of retry_with_backoff
pub fn retry_with_backoff_sync<T, F, E>(
    mut operation: F,
    config: &RetryConfig,
) -> Result<T, SystemMetricError>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let mut delay = config.initial_delay;
    
    for attempt in 1..=config.max_attempts {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::warn!("Attempt {}/{} failed: {}", attempt, config.max_attempts, e);
                
                if attempt == config.max_attempts {
                    return Err(SystemMetricError::RetryExhausted);
                }
                
                std::thread::sleep(delay);
                delay = std::cmp::min(
                    Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                    config.max_delay,
                );
            }
        }
    }
    
    Err(SystemMetricError::RetryExhausted)
}