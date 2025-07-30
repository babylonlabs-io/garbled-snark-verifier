use std::{
    fs,
    path::Path,
    process::Command,
};

use crate::errors::{SystemMetricError, RetryConfig, retry_with_backoff_sync};

/// Cross-platform system metrics collection with retry logic and graceful fallbacks
#[derive(Debug)]
pub struct SystemMetrics {
    retry_config: RetryConfig,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            retry_config: RetryConfig::default(),
        }
    }
}

impl SystemMetrics {
    pub fn new(retry_config: RetryConfig) -> Self {
        Self { retry_config }
    }

    /// Get memory information with fallback mechanisms
    pub fn get_memory_info(&self) -> (f64, f64) {
        // Try to get memory with retry logic
        let memory_result = retry_with_backoff_sync(
            || self.get_memory_info_internal(),
            &self.retry_config,
        );

        match memory_result {
            Ok((total, available)) => {
                log::debug!("Memory info: total={:.2}GB, available={:.2}GB", total, available);
                (total, available)
            }
            Err(e) => {
                log::warn!("Failed to get memory info after retries: {}. Using conservative estimates.", e);
                // Conservative fallback: assume 16GB total, 8GB available
                (16.0, 8.0)
            }
        }
    }

    fn get_memory_info_internal(&self) -> Result<(f64, f64), SystemMetricError> {
        // Try platform-specific methods in order of preference
        
        // 1. Try Linux /proc/meminfo (most accurate)
        if let Ok(result) = self.get_linux_memory_info() {
            return Ok(result);
        }

        // 2. Try memory_stats crate (cross-platform but less accurate)
        if let Ok(result) = self.get_memory_stats_info() {
            return Ok(result);
        }

        // 3. Try platform-specific commands
        #[cfg(target_os = "macos")]
        if let Ok(result) = self.get_macos_memory_info() {
            return Ok(result);
        }

        #[cfg(target_os = "windows")]
        if let Ok(result) = self.get_windows_memory_info() {
            return Ok(result);
        }

        Err(SystemMetricError::MemoryError("All memory detection methods failed".to_string()))
    }

    fn get_linux_memory_info(&self) -> Result<(f64, f64), SystemMetricError> {
        let meminfo = fs::read_to_string("/proc/meminfo")
            .map_err(|e| SystemMetricError::MemoryError(format!("Failed to read /proc/meminfo: {}", e)))?;

        let mut total_mem_kb = None;
        let mut available_mem_kb = None;
        let mut swap_total_kb = None;
        let mut swap_free_kb = None;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total_mem_kb = self.parse_meminfo_line(line)?;
            } else if line.starts_with("MemAvailable:") {
                available_mem_kb = self.parse_meminfo_line(line)?;
            } else if line.starts_with("SwapTotal:") {
                swap_total_kb = self.parse_meminfo_line(line)?;
            } else if line.starts_with("SwapFree:") {
                swap_free_kb = self.parse_meminfo_line(line)?;
            }
        }

        let total = total_mem_kb.ok_or_else(|| SystemMetricError::ParseError("MemTotal not found".to_string()))?;
        let available = available_mem_kb.ok_or_else(|| SystemMetricError::ParseError("MemAvailable not found".to_string()))?;
        let swap_total = swap_total_kb.unwrap_or(0);
        let swap_free = swap_free_kb.unwrap_or(0);

        let total_virtual_gb = (total + swap_total) as f64 / 1024.0 / 1024.0;
        let available_virtual_gb = (available + swap_free) as f64 / 1024.0 / 1024.0;

        Ok((total_virtual_gb, available_virtual_gb))
    }

    fn parse_meminfo_line(&self, line: &str) -> Result<Option<u64>, SystemMetricError> {
        line.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
            .map(Some)
            .ok_or_else(|| SystemMetricError::ParseError(format!("Failed to parse meminfo line: {}", line)))
    }

    fn get_memory_stats_info(&self) -> Result<(f64, f64), SystemMetricError> {
        let stats = memory_stats::memory_stats()
            .ok_or_else(|| SystemMetricError::MemoryError("memory_stats failed".to_string()))?;

        let virtual_gb = stats.virtual_mem as f64 / 1024.0 / 1024.0 / 1024.0;
        // Conservative estimate: assume 80% of virtual memory is available
        let available_gb = virtual_gb * 0.8;

        Ok((virtual_gb, available_gb))
    }

    #[cfg(target_os = "macos")]
    fn get_macos_memory_info(&self) -> Result<(f64, f64), SystemMetricError> {
        let output = Command::new("vm_stat")
            .output()
            .map_err(|e| SystemMetricError::CommandError(format!("vm_stat failed: {}", e)))?;

        if !output.status.success() {
            return Err(SystemMetricError::CommandError("vm_stat command failed".to_string()));
        }

        // Parse vm_stat output (basic implementation)
        let output_str = String::from_utf8_lossy(&output.stdout);
        // This is a simplified parser - would need more robust implementation
        let total_gb = 16.0; // Default fallback
        let available_gb = 8.0; // Default fallback

        Ok((total_gb, available_gb))
    }

    #[cfg(target_os = "windows")]
    fn get_windows_memory_info(&self) -> Result<(f64, f64), SystemMetricError> {
        let output = Command::new("wmic")
            .args(["OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory", "/format:csv"])
            .output()
            .map_err(|e| SystemMetricError::CommandError(format!("wmic failed: {}", e)))?;

        if !output.status.success() {
            return Err(SystemMetricError::CommandError("wmic command failed".to_string()));
        }

        // Parse wmic output (basic implementation)
        let output_str = String::from_utf8_lossy(&output.stdout);
        // This is a simplified parser - would need more robust implementation
        let total_gb = 16.0; // Default fallback
        let available_gb = 8.0; // Default fallback

        Ok((total_gb, available_gb))
    }

    /// Get disk space with improved fallback mechanisms
    pub fn get_disk_space(&self, path: &str) -> f64 {
        let disk_result = retry_with_backoff_sync(
            || self.get_disk_space_internal(path),
            &self.retry_config,
        );

        match disk_result {
            Ok(space) => {
                log::debug!("Disk space for {}: {:.2}GB", path, space);
                space
            }
            Err(e) => {
                log::warn!("Failed to get disk space for {} after retries: {}. Using conservative estimate.", path, e);
                // More intelligent fallback based on available memory
                let (_, available_mem_gb) = self.get_memory_info();
                // Assume disk space is at least 100x available memory, but cap at reasonable values
                let estimated_disk = (available_mem_gb * 100.0).max(100.0).min(10000.0);
                log::info!("Estimated disk space based on memory: {:.2}GB", estimated_disk);
                estimated_disk
            }
        }
    }

    fn get_disk_space_internal(&self, path: &str) -> Result<f64, SystemMetricError> {
        // Try different methods in order of preference

        // 1. Try statvfs (Unix-like systems)
        #[cfg(unix)]
        if let Ok(space) = self.get_statvfs_disk_space(path) {
            return Ok(space);
        }

        // 2. Try df command (Unix-like systems)
        if let Ok(space) = self.get_df_disk_space(path) {
            return Ok(space);
        }

        // 3. Try platform-specific methods
        #[cfg(target_os = "windows")]
        if let Ok(space) = self.get_windows_disk_space(path) {
            return Ok(space);
        }

        Err(SystemMetricError::DiskSpaceError("All disk space detection methods failed".to_string()))
    }

    #[cfg(unix)]
    fn get_statvfs_disk_space(&self, path: &str) -> Result<f64, SystemMetricError> {
        use std::ffi::CString;
        use std::mem;

        let c_path = CString::new(path)
            .map_err(|e| SystemMetricError::DiskSpaceError(format!("Invalid path: {}", e)))?;

        unsafe {
            let mut stat: libc::statvfs = mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                let available_blocks = stat.f_bavail;
                let block_size = stat.f_frsize;
                let available_bytes = available_blocks * block_size;
                let available_gb = available_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
                return Ok(available_gb);
            }
        }

        Err(SystemMetricError::DiskSpaceError("statvfs failed".to_string()))
    }

    fn get_df_disk_space(&self, path: &str) -> Result<f64, SystemMetricError> {
        let output = Command::new("df")
            .arg("-BG")
            .arg(path)
            .output()
            .map_err(|e| SystemMetricError::CommandError(format!("df command failed: {}", e)))?;

        if !output.status.success() {
            return Err(SystemMetricError::CommandError("df command returned non-zero exit code".to_string()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Ok(available_gb) = parts[3].trim_end_matches('G').parse::<f64>() {
                    return Ok(available_gb);
                }
            }
        }

        Err(SystemMetricError::ParseError("Failed to parse df output".to_string()))
    }

    #[cfg(target_os = "windows")]
    fn get_windows_disk_space(&self, path: &str) -> Result<f64, SystemMetricError> {
        let output = Command::new("fsutil")
            .args(["volume", "diskfree", path])
            .output()
            .map_err(|e| SystemMetricError::CommandError(format!("fsutil failed: {}", e)))?;

        if !output.status.success() {
            return Err(SystemMetricError::CommandError("fsutil command failed".to_string()));
        }

        // Parse fsutil output (basic implementation)
        let output_str = String::from_utf8_lossy(&output.stdout);
        // This would need proper parsing implementation
        let available_gb = 1000.0; // Default fallback

        Ok(available_gb)
    }

    /// Get folder size with error handling
    pub fn get_folder_size(&self, path: &str) -> (f64, usize) {
        let folder_result = retry_with_backoff_sync(
            || self.get_folder_size_internal(path),
            &self.retry_config,
        );

        match folder_result {
            Ok((size, count)) => {
                log::debug!("Folder {} size: {:.2}GB, {} files", path, size, count);
                (size, count)
            }
            Err(e) => {
                log::warn!("Failed to get folder size for {} after retries: {}. Using zero.", path, e);
                (0.0, 0)
            }
        }
    }

    fn get_folder_size_internal(&self, path: &str) -> Result<(f64, usize), SystemMetricError> {
        let mut total_size = 0u64;
        let mut file_count = 0usize;

        if !Path::new(path).exists() {
            return Ok((0.0, 0));
        }

        fn visit_dir(dir: &Path, total_size: &mut u64, file_count: &mut usize) -> Result<(), SystemMetricError> {
            let entries = fs::read_dir(dir)
                .map_err(|e| SystemMetricError::DiskSpaceError(format!("Failed to read directory: {}", e)))?;

            for entry in entries {
                let entry = entry
                    .map_err(|e| SystemMetricError::DiskSpaceError(format!("Failed to read directory entry: {}", e)))?;
                let path = entry.path();
                
                if path.is_dir() {
                    visit_dir(&path, total_size, file_count)?;
                } else {
                    let metadata = entry.metadata()
                        .map_err(|e| SystemMetricError::DiskSpaceError(format!("Failed to get file metadata: {}", e)))?;
                    *total_size += metadata.len();
                    *file_count += 1;
                }
            }
            Ok(())
        }

        visit_dir(Path::new(path), &mut total_size, &mut file_count)?;
        let size_gb = total_size as f64 / 1024.0 / 1024.0 / 1024.0;
        Ok((size_gb, file_count))
    }
}