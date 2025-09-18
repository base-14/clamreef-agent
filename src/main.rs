use clap::{Arg, Command};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use clamreef_agent::{
    clamav::{ClamAVClient, ClamAVClientImpl, ClamAVConnection},
    config::Config,
    error::{Error, Result},
    metrics::MetricsCollector,
    scheduler::Scheduler,
    telemetry::TelemetryExporter,
};

#[derive(Debug)]
struct Args {
    config_path: Option<PathBuf>,
    log_level: String,
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    // Initialize logging
    init_logging(&args.log_level)?;

    info!("Starting ClamReef Agent v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = if let Some(config_path) = &args.config_path {
        info!("Loading config from: {:?}", config_path);
        Config::load(config_path).await?
    } else {
        info!("Loading config from default locations");
        Config::load_from_default_locations().await?
    };

    if args.dry_run {
        info!("Configuration is valid. Dry run complete.");
        return Ok(());
    }

    // Create ClamAV client
    let clamav_connection = if let Some(socket_path) = &config.clamav.socket_path {
        ClamAVConnection::Unix {
            path: socket_path.clone(),
        }
    } else if let (Some(host), Some(port)) = (&config.clamav.tcp_host, config.clamav.tcp_port) {
        ClamAVConnection::Tcp {
            host: host.clone(),
            port,
        }
    } else {
        return Err(Error::Config("No ClamAV connection configured".to_string()));
    };

    let clamav_client = Arc::new(ClamAVClientImpl::new(clamav_connection).with_timeout(
        std::time::Duration::from_secs(config.clamav.scan_timeout_seconds),
    ));

    // Test ClamAV connection
    info!("Testing ClamAV connection...");
    match clamav_client.ping().await {
        Ok(true) => info!("ClamAV connection successful"),
        Ok(false) => {
            error!("ClamAV ping failed");
            return Err(Error::ClamAV("Ping failed".to_string()));
        }
        Err(e) => {
            error!("Failed to connect to ClamAV: {}", e);
            return Err(e);
        }
    }

    // Get ClamAV version info
    match clamav_client.version().await {
        Ok(version) => {
            info!(
                "ClamAV version: {} (database: {})",
                version.clamav, version.database
            );
        }
        Err(e) => {
            warn!("Could not get ClamAV version: {}", e);
        }
    }

    // Create metrics collector
    let metrics_collector = Arc::new(MetricsCollector::new());

    // Initialize telemetry
    let telemetry_exporter = Arc::new(TelemetryExporter::new(
        config.telemetry.clone(),
        Arc::clone(&metrics_collector),
        config.get_machine_name(),
        env!("CARGO_PKG_VERSION").to_string(),
    )?);

    // Create scheduler
    let scheduler = Arc::new(Scheduler::new(
        config.rules.clone(),
        Arc::clone(&clamav_client) as Arc<dyn clamreef_agent::clamav::ClamAVClient>,
        Arc::clone(&metrics_collector),
    ));

    // Start telemetry export loop
    let telemetry_handle = {
        let exporter = Arc::clone(&telemetry_exporter);
        tokio::spawn(async move {
            exporter.start_export_loop().await;
        })
    };

    // Start scheduler
    let scheduler_handle = {
        let scheduler = Arc::clone(&scheduler);
        tokio::spawn(async move {
            if let Err(e) = scheduler.start().await {
                error!("Scheduler error: {}", e);
            }
        })
    };

    info!(
        "ClamReef Agent started successfully with {} rules",
        config.rules.len()
    );

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    // Graceful shutdown
    info!("Shutting down...");

    // Cancel tasks
    telemetry_handle.abort();
    scheduler_handle.abort();

    // Shutdown telemetry
    if let Err(e) = telemetry_exporter.shutdown().await {
        error!("Error during telemetry shutdown: {}", e);
    }

    info!("ClamReef Agent shutdown complete");
    Ok(())
}

fn parse_args() -> Args {
    let matches = Command::new("clamreef-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .about("ClamReef Agent - Control plane agent for ClamAV")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .num_args(1),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info")
                .num_args(1),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Validate configuration and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    Args {
        config_path: matches.get_one::<String>("config").map(PathBuf::from),
        log_level: matches.get_one::<String>("log-level").unwrap().clone(),
        dry_run: matches.get_flag("dry-run"),
    }
}

fn init_logging(log_level: &str) -> Result<()> {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => return Err(Error::Config(format!("Invalid log level: {}", log_level))),
    };

    let env_filter = EnvFilter::from_default_env()
        .add_directive(format!("clamreef_agent={}", level).parse().unwrap());

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(env_filter)
        .init();

    Ok(())
}
