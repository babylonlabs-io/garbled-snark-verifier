use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::process_monitor::{MonitorSnapshot, ProcessMonitor, ThreadStatus};

pub struct TuiApp {
    should_quit: bool,
    last_update: Instant,
    refresh_interval: Duration,
    monitor: Option<std::sync::Arc<std::sync::Mutex<ProcessMonitor>>>,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            last_update: Instant::now(),
            refresh_interval: Duration::from_secs(2), // Faster refresh for real-time monitoring
            monitor: ProcessMonitor::instance(),
        }
    }

    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main loop
        let result = self.run_app(&mut terminal);

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    fn run_app(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            // Draw UI
            terminal.draw(|f| self.ui(f))?;

            // Handle input with timeout
            let timeout = Duration::from_millis(250);
            if event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') => {
                        self.should_quit = true;
                    }
                    KeyCode::Char('r') => {
                        self.last_update = Instant::now()
                            .checked_sub(self.refresh_interval)
                            .unwrap_or(Instant::now());
                    }
                    _ => {}
                }
            }

            // Auto-refresh check
            if self.last_update.elapsed() >= self.refresh_interval {
                self.last_update = Instant::now();
                // Trigger refresh if needed
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    fn ui(&self, f: &mut Frame) {
        let size = f.area();

        // Main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(8),    // Thread list
                Constraint::Length(4), // System performance
                Constraint::Length(4), // Storage status
                Constraint::Length(1), // Controls
            ])
            .split(size);

        // Get current snapshot
        let snapshot = if let Some(monitor) = &self.monitor {
            if let Ok(guard) = monitor.lock() {
                Some(guard.get_snapshot())
            } else {
                None
            }
        } else {
            None
        };

        // Render components
        self.render_header(f, chunks[0], &snapshot);
        self.render_thread_list(f, chunks[1], &snapshot);
        self.render_system_performance(f, chunks[2], &snapshot);
        self.render_storage_status(f, chunks[3], &snapshot);
        self.render_controls(f, chunks[4]);
    }

    fn render_header(&self, f: &mut Frame, area: Rect, snapshot: &Option<MonitorSnapshot>) {
        let title = if let Some(snap) = snapshot {
            format!(
                "Garbled Circuit Monitor [Process: {:.1}GB/{:.0}GB] Runtime: {}",
                snap.system.process_memory_gb,
                snap.system.total_memory_gb,
                format_duration(snap.runtime)
            )
        } else {
            "Garbled Circuit Monitor [Initializing...]".to_string()
        };

        let header_info = if let Some(snap) = snapshot {
            format!(
                "Tasks: {}/{} (✅{} ❌{}) | Workers: {}/{} | Circuit: {} wires | Progress: {:.1}%",
                snap.system.completed_tasks + snap.system.failed_tasks + snap.system.active_workers,
                snap.system.total_garbling_tasks,
                snap.system.completed_tasks,
                snap.system.failed_tasks,
                snap.system.active_workers,
                snap.system.max_workers,
                format_large_number(snap.circuit.num_wire),
                (snap.system.completed_tasks as f64 / snap.system.total_garbling_tasks as f64)
                    * 100.0
            )
        } else {
            "Waiting for data...".to_string()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(header_info)
            .block(block)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn render_thread_list(&self, f: &mut Frame, area: Rect, snapshot: &Option<MonitorSnapshot>) {
        let thread_count = if let Some(snap) = snapshot {
            snap.threads.len()
        } else {
            0
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!("Active Workers [{thread_count}]"))
            .border_style(Style::default().fg(Color::Green));

        let items: Vec<ListItem> = if let Some(snap) = snapshot {
            if snap.threads.is_empty() {
                vec![ListItem::new("No worker threads detected")]
            } else {
                // Threads are already sorted by ProcessMonitor for performance
                snap.threads
                    .iter()
                    .map(|thread| {
                        let status_char = match thread.status {
                            ThreadStatus::Starting => "⏳",
                            ThreadStatus::Running => "🔄",
                            ThreadStatus::Completing => "⏳",
                            ThreadStatus::Finished => "✅",
                            ThreadStatus::Error => "❌",
                        };

                        let content = if thread.status == ThreadStatus::Error {
                            // Show error message for failed threads
                            let error_msg =
                                thread.error_message.as_deref().unwrap_or("Unknown error");
                            format!("T{}: ERROR - {}", thread.thread_id, error_msg)
                        } else if thread.status == ThreadStatus::Finished {
                            // For finished threads, show only hashes (no speed/timer updates)
                            let hash_display = if let Some(ref hash) = thread.input_hash160 {
                                format!("Input: {}...", &hash[0..8.min(hash.len())])
                            } else {
                                "Input: N/A".to_string()
                            };
                            // TODO: Add output hash when available from ProcessMonitor
                            format!(
                                "T{}: COMPLETED | {} | Runtime: {}",
                                thread.thread_id,
                                hash_display,
                                format_duration(thread.duration)
                            )
                        } else {
                            // Normal progress display for active threads
                            let progress_bar = create_progress_bar(thread.progress_percent, 10);
                            let hash_display = if let Some(ref hash) = thread.input_hash160 {
                                format!(" | Hash: {}...", &hash[0..8.min(hash.len())])
                            } else {
                                String::new()
                            };
                            format!(
                                "T{}: {} {:.1}% | {:.2}M g/s | {} | {}M gates{}",
                                thread.thread_id,
                                progress_bar,
                                thread.progress_percent,
                                thread.gates_per_second / 1_000_000.0,
                                format_duration(thread.duration),
                                thread.current_gate / 1_000_000,
                                hash_display
                            )
                        };

                        if thread.status == ThreadStatus::Error {
                            ListItem::new(Line::from(vec![
                                Span::raw(status_char),
                                Span::raw(" "),
                                Span::styled(content, Style::default().fg(Color::Red)),
                            ]))
                        } else {
                            ListItem::new(Line::from(vec![
                                Span::raw(status_char),
                                Span::raw(" "),
                                Span::raw(content),
                            ]))
                        }
                    })
                    .collect()
            }
        } else {
            vec![ListItem::new("No worker data available")]
        };

        let list = List::new(items)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    }

    fn render_system_performance(
        &self,
        f: &mut Frame,
        area: Rect,
        snapshot: &Option<MonitorSnapshot>,
    ) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("System Performance")
            .border_style(Style::default().fg(Color::Yellow));

        let content = if let Some(snap) = snapshot {
            let global_progress = (snap.system.completed_tasks as f64
                / snap.system.total_garbling_tasks as f64)
                * 100.0;
            let remaining_tasks = snap.system.total_garbling_tasks.saturating_sub(
                snap.system.completed_tasks + snap.system.failed_tasks + snap.system.active_workers,
            );

            let eta = if snap.total_speed > 0.0 {
                let remaining_gates = snap
                    .circuit
                    .total_gates
                    .saturating_sub(snap.total_gates_processed);
                let eta_seconds = remaining_gates as f64 / snap.total_speed;
                format!(
                    "ETA: {}",
                    format_duration(Duration::from_secs(eta_seconds as u64))
                )
            } else {
                "ETA: Calculating...".to_string()
            };

            format!(
                "Global Tasks: {} {:.1}% | Waiting: {} | Total Speed: {:.2}M gates/s | {}\nMemory Rate: +{:.1}GB/h | Runtime: {} | Peak: {:.1}GB",
                create_progress_bar(global_progress, 20),
                global_progress,
                remaining_tasks,
                snap.total_speed / 1_000_000.0,
                eta,
                snap.system.memory_rate_gb_per_hour,
                format_duration(snap.runtime),
                snap.system.memory_peak_gb
            )
        } else {
            "Waiting for performance data...".to_string()
        };

        let paragraph = Paragraph::new(content)
            .block(block)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn render_storage_status(&self, f: &mut Frame, area: Rect, snapshot: &Option<MonitorSnapshot>) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Storage Status")
            .border_style(Style::default().fg(Color::Magenta));

        let content = if let Some(snap) = snapshot {
            format!(
                "Save Folder: {:.1}GB | Files: {} | Disk Free: {:.1}GB\nI/O Rate: Calculating... | Pending Tasks: {}",
                snap.system.save_folder_size_gb,
                snap.system.files_written,
                snap.system.disk_free_gb,
                snap.system.pending_tasks
            )
        } else {
            "Waiting for storage data...".to_string()
        };

        let paragraph = Paragraph::new(content)
            .block(block)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }

    fn render_controls(&self, f: &mut Frame, area: Rect) {
        let controls = "[q]uit [r]efresh";
        let paragraph = Paragraph::new(controls).style(Style::default().fg(Color::Gray));

        f.render_widget(paragraph, area);
    }
}

fn create_progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64) as usize;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn format_large_number(num: usize) -> String {
    if num >= 1_000_000_000 {
        format!("{:.1}B", num as f64 / 1_000_000_000.0)
    } else if num >= 1_000_000 {
        format!("{:.1}M", num as f64 / 1_000_000.0)
    } else if num >= 1_000 {
        format!("{:.1}K", num as f64 / 1_000.0)
    } else {
        format!("{num}")
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = TuiApp::new();
    app.run()
}
